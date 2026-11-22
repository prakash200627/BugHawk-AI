"""Run ProjectDiscovery Nuclei against URLs the worker already verified.

The template directory is the packaged header-check set. Its file names and
SHA-256 digests are fixed here. A failed review cancels the run.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from app.config import settings
from app.scanners.subfinder import is_safe_domain, sanitize_tool_text

_EXECUTABLE_NAME = {"nuclei", "nuclei.exe"}
_UNSAFE_EXECUTABLE = set("\x00\n\r;&|$`<>\"'")
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "nuclei_templates" / "safe"
ALLOWED_SEVERITY = {
    "bughawk-missing-hsts.yaml": "info",
    "bughawk-missing-content-type-options.yaml": "info",
    "bughawk-missing-frame-options.yaml": "low",
    "bughawk-missing-csp.yaml": "info",
    "bughawk-missing-referrer-policy.yaml": "info",
}
ALLOWED_DIGESTS = {
    "bughawk-missing-hsts.yaml": "846b2d4a7af816ca5ff2918d74ef499d82b3e18062c776568f9a6a1b71703fb5",
    "bughawk-missing-content-type-options.yaml": "58f8956f9dbb22f6c38ead2c65c740031fa1d7e7ad14cf99f942e29a831c5bf4",
    "bughawk-missing-frame-options.yaml": "91bb5a119c9cf071c6e27a0137483aa771e56535a0dff34b9696ffe2e1d1cf60",
    "bughawk-missing-csp.yaml": "c6a1a1fabebae7f59a38ec73b79a85ac7eb4e7ea103263a8ef9f979355080ce5",
    "bughawk-missing-referrer-policy.yaml": "f44d95c0bf8c23b032358952529d149fd43671aa983bdd6baf7338f05e108c2d",
}
ALLOWED_TEMPLATE_IDS = frozenset(name.removesuffix(".yaml") for name in ALLOWED_DIGESTS)
SEVERITY_NAMES = {"info", "low", "medium", "high", "critical", "unknown"}
_FORBIDDEN = (
    "interactsh",
    "oast.",
    "fuzz",
    "headless",
    "javascript",
    "code:",
    "dns:",
    "brute",
    "dos",
    "rce",
    "sqli",
    "cmd",
    "exec",
    "payload",
    "unsafe: true",
    "redirects: true",
    "method: post",
    "method: put",
    "raw:",
)
_PRIVATE_IP = (
    r"(?:^|\b)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})(?:\b|$)"
)
_SECRET = re.compile(r"(?i)(authorization|set-cookie|cookie|token|password|secret)\s*[:=]")


class NucleiConfigError(Exception):
    """NUCLEI_PATH is not the nuclei program."""


class NucleiTemplateError(Exception):
    """The packaged templates failed the safety review."""


@dataclass
class NucleiMatch:
    template_id: str
    name: str
    severity: str
    url: str
    hostname: str
    detected_at: str | None = None
    matcher_name: str | None = None


@dataclass
class NucleiOutcome:
    exit_code: int | None
    matches: list[NucleiMatch] = field(default_factory=list)
    invalid_lines: int = 0
    message: str = ""
    timed_out: bool = False
    too_large: bool = False
    failed: bool = False


def resolve_nuclei_executable(configured: str | None = None) -> str:
    """Use NUCLEI_PATH only when it names the nuclei program."""
    text = (configured if configured is not None else settings.nuclei_path).strip()
    if not text:
        text = "nuclei"
    if len(text) > 512 or any(char in _UNSAFE_EXECUTABLE for char in text):
        raise NucleiConfigError("NUCLEI_PATH is not a single executable.")
    if os.path.basename(text).lower() not in _EXECUTABLE_NAME:
        raise NucleiConfigError("NUCLEI_PATH must point at the nuclei program.")
    return text


def review_templates(directory: Path | None = None) -> list[Path]:
    """Accept only the reviewed files, unchanged, with no extras in the directory."""
    folder = directory if directory is not None else TEMPLATE_DIR
    if not folder.is_dir():
        raise NucleiTemplateError("The reviewed Nuclei template directory is missing.")
    present = sorted(path.name for path in folder.iterdir() if path.is_file())
    expected = sorted(ALLOWED_DIGESTS)
    if present != expected:
        raise NucleiTemplateError("The Nuclei template directory does not match the reviewed set.")
    paths: list[Path] = []
    for name in expected:
        path = folder / name
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != ALLOWED_DIGESTS[name]:
            raise NucleiTemplateError("A Nuclei template does not match its reviewed digest.")
        text = data.decode("utf-8")
        lowered = text.lower()
        template_id = name.removesuffix(".yaml")
        if f"id: {template_id}" not in text:
            raise NucleiTemplateError("A Nuclei template id does not match its file name.")
        if f"severity: {ALLOWED_SEVERITY[name]}" not in text:
            raise NucleiTemplateError("A Nuclei template severity is not the reviewed value.")
        if "method: GET" not in text or "redirects: false" not in text or "max-redirects: 0" not in text:
            raise NucleiTemplateError("A Nuclei template is not limited to one GET without redirects.")
        if '"{{BaseURL}}"' not in text:
            raise NucleiTemplateError("A Nuclei template does not use the base URL only.")
        if any(token in lowered for token in _FORBIDDEN):
            raise NucleiTemplateError("A Nuclei template contains a forbidden capability.")
        paths.append(path)
    return paths


def _clean_text(value: str, limit: int) -> str:
    text = sanitize_tool_text(value.encode("utf-8", errors="replace"))
    text = re.sub(_PRIVATE_IP, "[redacted]", text)
    return text[:limit].strip()


def normalize_target_url(url: str) -> tuple[str, str] | None:
    """Keep an origin URL on port 80 or 443. Drop queries and other ports."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return None
    expected = 443 if parsed.scheme == "https" else 80
    if parsed.port not in (None, expected):
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not is_safe_domain(host) or parsed.query or parsed.fragment:
        return None
    if parsed.path not in ("", "/"):
        return None
    return f"{parsed.scheme}://{host}", host


def _matched_url(url: str, allowed_hosts: set[str]) -> tuple[str, str] | None:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return None
    expected = 443 if parsed.scheme == "https" else 80
    if parsed.port not in (None, expected):
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in allowed_hosts or not is_safe_domain(host) or parsed.query or parsed.fragment:
        return None
    path = parsed.path or "/"
    if len(path) > 200 or ".." in path:
        return None
    return f"{parsed.scheme}://{host}{path}", host


def parse_nuclei_line(line: str, allowed_hosts: set[str]) -> NucleiMatch | None:
    """Keep one JSON object when its template and URL are on the reviewed list."""
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(item, dict):
        return None
    template_id = item.get("template-id")
    if not isinstance(template_id, str) or template_id not in ALLOWED_TEMPLATE_IDS:
        return None
    matched = item.get("matched-at")
    if not isinstance(matched, str):
        return None
    located = _matched_url(matched, allowed_hosts)
    if located is None:
        return None
    url, host = located
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    severity = str(info.get("severity") or "").strip().lower()
    if severity == "informational":
        severity = "info"
    if severity not in SEVERITY_NAMES:
        return None
    name = info.get("name")
    title = template_id
    if isinstance(name, str) and name.strip() and not _SECRET.search(name):
        title = _clean_text(name, 180) or template_id
    detected = item.get("timestamp")
    detected_at = detected.strip()[:40] if isinstance(detected, str) and detected.strip() else None
    matcher = item.get("matcher-name")
    matcher_name = None
    if isinstance(matcher, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", matcher):
        matcher_name = matcher
    return NucleiMatch(
        template_id=template_id,
        name=title,
        severity=severity,
        url=url,
        hostname=host,
        detected_at=detected_at,
        matcher_name=matcher_name,
    )


def parse_nuclei_output(stdout: bytes, allowed_hosts: set[str]) -> tuple[list[NucleiMatch], int]:
    matches: list[NucleiMatch] = []
    seen: set[tuple[str, str]] = set()
    invalid = 0
    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = parse_nuclei_line(line, allowed_hosts)
        if match is None:
            invalid += 1
            continue
        key = (match.template_id, match.url)
        if key in seen:
            continue
        seen.add(key)
        matches.append(match)
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


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _scrubbed_env(home: str) -> dict[str, str]:
    """Hide host Nuclei config and template directories from this process."""
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("NUCLEI")}
    env["HOME"] = home
    env["XDG_CONFIG_HOME"] = home
    env["XDG_CONFIG_DIRS"] = home
    return env


def run_nuclei(
    urls: list[str],
    *,
    executable: str | None = None,
    timeout_seconds: int | None = None,
    job_timeout_seconds: int | None = None,
    rate_limit: int | None = None,
    concurrency: int | None = None,
    bulk_size: int | None = None,
    max_output_bytes: int | None = None,
) -> NucleiOutcome:
    """Probe the given origins. Template paths and tags are not arguments."""
    try:
        review_templates(TEMPLATE_DIR)
    except NucleiTemplateError as exc:
        return NucleiOutcome(exit_code=None, failed=True, message=str(exc))
    chosen: list[str] = []
    hosts: set[str] = set()
    for url in urls:
        located = normalize_target_url(url)
        if located is None:
            continue
        canonical, host = located
        if canonical not in chosen:
            chosen.append(canonical)
            hosts.add(host)
    if not chosen:
        return NucleiOutcome(exit_code=0, message="No URLs to scan.")
    try:
        program = resolve_nuclei_executable(executable)
    except NucleiConfigError as exc:
        return NucleiOutcome(exit_code=None, failed=True, message=str(exc))

    request_timeout = settings.nuclei_timeout_seconds if timeout_seconds is None else timeout_seconds
    job_timeout = settings.nuclei_job_timeout_seconds if job_timeout_seconds is None else job_timeout_seconds
    limit_rate = min(10, max(1, int(settings.nuclei_rate_limit if rate_limit is None else rate_limit)))
    workers = min(2, max(1, int(settings.nuclei_concurrency if concurrency is None else concurrency)))
    bulk = min(5, max(1, int(settings.nuclei_bulk_size if bulk_size is None else bulk_size)))
    limit = settings.nuclei_max_output_bytes if max_output_bytes is None else max_output_bytes
    argv = [
        program,
        "-silent",
        "-jsonl",
        "-omit-raw",
        "-omit-template",
        "-no-interactsh",
        "-disable-update-check",
        "-rate-limit",
        str(limit_rate),
        "-concurrency",
        str(workers),
        "-bulk-size",
        str(bulk),
        "-timeout",
        str(int(request_timeout)),
        "-severity",
        "info,low",
        "-exclude-type",
        "dns,file,headless,tcp,workflow,ssl,websocket,whois,code,javascript",
        "-templates",
        str(TEMPLATE_DIR),
    ]
    home = tempfile.mkdtemp(prefix="bughawk-nuclei-")
    try:
        return _run_process(
            argv,
            chosen,
            hosts,
            home,
            job_timeout,
            limit,
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _run_process(argv, urls, hosts, home, job_timeout, limit) -> NucleiOutcome:
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_scrubbed_env(home),
        )
    except OSError:
        return NucleiOutcome(exit_code=None, failed=True, message="Nuclei could not be started.")
    payload = ("\n".join(urls) + "\n").encode("utf-8")
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
        proc.stdin.write(payload)
        proc.stdin.close()
    except (BrokenPipeError, OSError, ValueError):
        pass
    try:
        proc.wait(timeout=job_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill(proc)
    if overflow and proc.poll() is None:
        _kill(proc)
    for reader in readers:
        reader.join(timeout=5)
    if timed_out:
        return NucleiOutcome(exit_code=None, timed_out=True, failed=True, message="Nuclei timed out.")
    if overflow:
        return NucleiOutcome(
            exit_code=proc.returncode,
            too_large=True,
            failed=True,
            message="Nuclei output exceeded the size limit.",
        )
    stdout = stdout_box[0] if stdout_box else b""
    stderr = stderr_box[0] if stderr_box else b""
    note = sanitize_tool_text(stderr)
    matches, invalid = parse_nuclei_output(stdout, hosts)
    if proc.returncode != 0:
        message = f"Nuclei exited with status {proc.returncode}."
        if note:
            message = f"{message} {note}"
        return NucleiOutcome(
            exit_code=proc.returncode,
            matches=[],
            invalid_lines=invalid,
            failed=True,
            message=message[:500],
        )
    return NucleiOutcome(exit_code=0, matches=matches, invalid_lines=invalid, message=note)
