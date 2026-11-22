"""Run Semgrep against a directory this process created from a stored archive.

The ruleset is the packaged files below. Their normalized SHA-256 values are fixed.
An arbitrary path, rule, or command from the API is refused.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from app.config import settings
from app.scanners.subfinder import sanitize_tool_text

_EXECUTABLE_NAME = {"semgrep", "semgrep.exe"}
_UNSAFE_EXECUTABLE = set("\x00\n\r;&|$`<>\"'")
RULE_DIR = Path(__file__).resolve().parent.parent / "semgrep_rules"
ALLOWED_RULES = {
    "python-eval.yaml": "6f37e827f9f6863454f4173c6c7834381cb98ce3f06aca834c218d1504504c68",
    "python-subprocess-shell.yaml": "ca45deb39a09515b42a0fdee72bb6dba6e198d1cbb12b1aa9f73187c600bae02",
    "javascript-eval.yaml": "b1c2e693c9a52bd150382a7163735c1678abe66c86d1977e61e0b1f41d5f3565",
}
ALLOWED_RULE_IDS = frozenset({
    "bughawk-python-eval",
    "bughawk-python-subprocess-shell",
    "bughawk-javascript-eval",
})
ALLOWED_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx"}
_BLOCKED_SUFFIXES = {".env", ".pem", ".key", ".p12", ".pfx", ".kdb", ".keystore"}
_SEVERITY = {"INFO": "info", "WARNING": "medium", "ERROR": "high"}
_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|authorization|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]"
)
_APPROVED: set[Path] = set()
MAX_ARCHIVE_BYTES = 2_000_000
MAX_FILE_BYTES = 200_000
MAX_FILES = 100

SOURCE_PREREQUISITE = (
    "Semgrep did not scan any files. This project has no uploaded source archive "
    "and no authorized repository connection."
)


class SemgrepConfigError(Exception):
    """SEMGREP_PATH is not the semgrep program."""


class SemgrepRuleError(Exception):
    """The packaged rules failed review."""


@dataclass
class SemgrepMatch:
    rule_id: str
    path: str
    line: int
    severity: str
    evidence: str


@dataclass
class SemgrepOutcome:
    exit_code: int | None
    matches: list[SemgrepMatch] = field(default_factory=list)
    invalid_lines: int = 0
    message: str = ""
    timed_out: bool = False
    too_large: bool = False
    failed: bool = False


def load_source_bundle(db, project_id: str) -> bytes | None:
    """Return a stored source archive for this project.

    No upload table and no repository connection exist, so this is always empty.
    """
    del db, project_id
    return None


def resolve_semgrep_executable(configured: str | None = None) -> str:
    text = (configured if configured is not None else settings.semgrep_path).strip()
    if not text:
        text = "semgrep"
    if len(text) > 512 or any(char in _UNSAFE_EXECUTABLE for char in text):
        raise SemgrepConfigError("SEMGREP_PATH is not a single executable.")
    if os.path.basename(text).lower() not in _EXECUTABLE_NAME:
        raise SemgrepConfigError("SEMGREP_PATH must point at the semgrep program.")
    return text


def review_rules(directory: Path | None = None) -> list[Path]:
    folder = directory if directory is not None else RULE_DIR
    if not folder.is_dir():
        raise SemgrepRuleError("The reviewed Semgrep ruleset is missing.")
    present = sorted(path.name for path in folder.iterdir() if path.is_file())
    expected = sorted(ALLOWED_RULES)
    if present != expected:
        raise SemgrepRuleError("The Semgrep ruleset does not match the reviewed set.")
    paths = []
    for name in expected:
        path = folder / name
        data = path.read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != ALLOWED_RULES[name]:
            raise SemgrepRuleError("A Semgrep rule does not match its reviewed digest.")
        text = data.decode("utf-8").lower()
        if "pattern-where" in text or "metavariable-pattern" in text or "rce" in text:
            raise SemgrepRuleError("A Semgrep rule is not limited to a pattern.")
        paths.append(path)
    return paths


def allocate_source_directory() -> Path:
    path = Path(tempfile.mkdtemp(prefix="bughawk-semgrep-")).resolve()
    _APPROVED.add(path)
    return path


def release_source_directory(path: Path) -> None:
    resolved = path.resolve()
    _APPROVED.discard(resolved)
    shutil.rmtree(resolved, ignore_errors=True)


def _safe_member(name: str) -> Path | None:
    if not name or name.endswith("/"):
        return None
    parts = Path(name).parts
    if not parts or name.startswith("/") or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
        raise SemgrepConfigError("The archive tried to escape its directory.")
    if any(part in {"", ".", ".."} for part in parts):
        raise SemgrepConfigError("The archive tried to escape its directory.")
    relative = Path(*parts)
    suffix = relative.suffix.lower()
    if suffix in _BLOCKED_SUFFIXES or relative.name.lower() in {".env", "id_rsa", "id_dsa"}:
        return None
    if suffix not in ALLOWED_SUFFIXES:
        return None
    return relative


def extract_source_archive(payload: bytes, destination: Path) -> int:
    """Unpack an archive into a directory this process allocated. Reject path escape."""
    if destination.resolve() not in _APPROVED:
        raise SemgrepConfigError("Refusing to extract outside an allocated source directory.")
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise SemgrepConfigError("The source archive exceeds the size limit.")
    stored = 0
    with zipfile.ZipFile(BytesIO(payload)) as archive:
        for info in archive.infolist():
            relative = _safe_member(info.filename)
            if relative is None:
                continue
            if info.file_size > MAX_FILE_BYTES:
                continue
            target = (destination / relative).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise SemgrepConfigError("The archive tried to escape its directory.")
            if stored >= MAX_FILES:
                break
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(info)
            if len(data) > MAX_FILE_BYTES:
                continue
            target.write_bytes(data)
            stored += 1
    return stored


def _clean_evidence(value: str) -> str:
    text = sanitize_tool_text(value.encode("utf-8", errors="replace"))
    if _SECRET.search(text):
        return "[redacted]"
    return text[:240]


def parse_semgrep_output(raw: bytes, root: Path) -> tuple[list[SemgrepMatch], int]:
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError:
        return [], 1
    if not isinstance(payload, dict):
        return [], 1
    matches = []
    invalid = 0
    seen = set()
    root_resolved = root.resolve()
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            invalid += 1
            continue
        rule_id = item.get("check_id") or ""
        if isinstance(rule_id, str) and rule_id.startswith("."):
            rule_id = rule_id.split(".")[-1]
        if rule_id not in ALLOWED_RULE_IDS:
            invalid += 1
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            invalid += 1
            continue
        candidate = Path(raw_path)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(root_resolved)
            except ValueError:
                invalid += 1
                continue
        else:
            if ".." in candidate.parts:
                invalid += 1
                continue
            relative = candidate
        if relative.suffix.lower() not in ALLOWED_SUFFIXES:
            invalid += 1
            continue
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        line = start.get("line")
        if not isinstance(line, int) or line < 1 or line > 1_000_000:
            invalid += 1
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        severity = _SEVERITY.get(str(extra.get("severity") or "").upper())
        if severity is None:
            invalid += 1
            continue
        evidence = _clean_evidence(str(extra.get("lines") or extra.get("message") or rule_id))
        key = (rule_id, relative.as_posix(), line)
        if key in seen:
            continue
        seen.add(key)
        matches.append(SemgrepMatch(rule_id, relative.as_posix(), line, severity, evidence))
    return matches, invalid


def _drain(stream, limit: int, sink: list[bytes], overflow: list[bool]) -> None:
    chunks: list[bytes] = []
    total = 0
    while stream is not None:
        chunk = stream.read(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            overflow.append(True)
            break
        chunks.append(chunk)
    sink.append(b"".join(chunks))


def _limit_resources() -> None:
    try:
        import resource
    except ImportError:
        return
    ceiling = 512 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))


def run_semgrep(
    scan_dir: Path,
    *,
    executable: str | None = None,
    timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
) -> SemgrepOutcome:
    """Scan one allocated directory with the reviewed rules. shell is disabled."""
    resolved = Path(scan_dir).resolve()
    if resolved not in _APPROVED or not resolved.is_dir():
        return SemgrepOutcome(exit_code=None, failed=True, message="Semgrep refused a directory it did not allocate.")
    try:
        review_rules(RULE_DIR)
        program = resolve_semgrep_executable(executable)
    except (SemgrepRuleError, SemgrepConfigError) as exc:
        return SemgrepOutcome(exit_code=None, failed=True, message=str(exc))
    timeout = settings.semgrep_timeout_seconds if timeout_seconds is None else timeout_seconds
    limit = settings.semgrep_max_output_bytes if max_output_bytes is None else max_output_bytes
    argv = [
        program,
        "--config",
        str(RULE_DIR),
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--jobs",
        "1",
        "--timeout",
        str(int(timeout)),
        "--max-target-bytes",
        str(MAX_FILE_BYTES),
        "--exclude",
        "*.env",
        "--exclude",
        "*.pem",
        "--exclude",
        "*.key",
        str(resolved),
    ]
    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "shell": False,
    }
    if os.name != "nt":
        popen_kwargs["preexec_fn"] = _limit_resources
    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except OSError:
        return SemgrepOutcome(exit_code=None, failed=True, message="Semgrep could not be started.")
    stdout_box: list[bytes] = []
    stderr_box: list[bytes] = []
    overflow: list[bool] = []
    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, limit, stdout_box, overflow), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, 16384, stderr_box, overflow), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=5)
    if timed_out:
        return SemgrepOutcome(exit_code=None, timed_out=True, failed=True, message="Semgrep timed out.")
    if overflow:
        return SemgrepOutcome(exit_code=proc.returncode, too_large=True, failed=True, message="Semgrep output exceeded the size limit.")
    stdout = stdout_box[0] if stdout_box else b""
    note = sanitize_tool_text(stderr_box[0] if stderr_box else b"")
    # Semgrep exits 1 when it finds issues. Treat 0 and 1 as finished output.
    if proc.returncode not in (0, 1):
        message = f"Semgrep exited with status {proc.returncode}."
        if note:
            message = f"{message} {note}"
        return SemgrepOutcome(exit_code=proc.returncode, failed=True, message=message[:500])
    matches, invalid = parse_semgrep_output(stdout, resolved)
    return SemgrepOutcome(exit_code=proc.returncode, matches=matches, invalid_lines=invalid, message=note)
