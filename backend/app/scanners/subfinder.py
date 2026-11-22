"""Run ProjectDiscovery Subfinder as a passive subdomain lookup.

The domain is one argument. The command is never passed through a shell.
"""
import re
import subprocess
import threading
from dataclasses import dataclass, field

from app.config import settings
from app.core.scope_guard import _is_valid_hostname

_EXECUTABLE_NAME = {"subfinder", "subfinder.exe"}
_UNSAFE_EXECUTABLE = set("\x00\n\r;&|$`<>\"'")
_HOST_LINE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class SubfinderTimeout(Exception):
    """The process exceeded the configured deadline."""


class SubfinderConfigError(Exception):
    """SUBFINDER_PATH is not the subfinder program."""


@dataclass
class SubfinderOutcome:
    exit_code: int | None
    hosts: list[str] = field(default_factory=list)
    message: str = ""
    timed_out: bool = False
    too_large: bool = False
    failed: bool = False


def is_safe_domain(domain: str) -> bool:
    """True when the domain can be one argv element and is a hostname."""
    if not domain or domain.startswith("-") or len(domain) > 253:
        return False
    return bool(_HOST_LINE.match(domain)) and _is_valid_hostname(domain)


def resolve_subfinder_executable(configured: str | None = None) -> str:
    """Use SUBFINDER_PATH only when it names the subfinder binary."""
    text = (configured if configured is not None else settings.subfinder_path).strip()
    if not text:
        text = "subfinder"
    if len(text) > 512 or any(char in _UNSAFE_EXECUTABLE for char in text):
        raise SubfinderConfigError("SUBFINDER_PATH is not a single executable.")
    if text.replace("\\", "/").rsplit("/", 1)[-1].lower() not in _EXECUTABLE_NAME:
        raise SubfinderConfigError("SUBFINDER_PATH must point at the subfinder program.")
    return text


def parse_subfinder_hosts(stdout: bytes) -> list[str]:
    """Keep unique hostnames. Drop blanks, wildcards, addresses, and junk lines."""
    found: list[str] = []
    seen: set[str] = set()
    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        host = raw_line.strip().lower().rstrip(".")
        if not host or host.startswith("*.") or host.startswith("-"):
            continue
        if not is_safe_domain(host) or host in seen:
            continue
        seen.add(host)
        found.append(host)
    return found


def sanitize_tool_text(raw: bytes) -> str:
    """Short single-line tool text with connection URLs removed."""
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp)(?:\+[a-z0-9]+)?://\S+",
        "[redacted]",
        text,
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text[:300]


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


def run_subfinder(
    domain: str,
    *,
    executable: str | None = None,
    timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
) -> SubfinderOutcome:
    """Run `subfinder -silent -d <domain>` and return parsed hostnames."""
    if not is_safe_domain(domain):
        return SubfinderOutcome(exit_code=None, failed=True, message="Domain is not safe to pass to Subfinder.")
    try:
        program = resolve_subfinder_executable(executable)
    except SubfinderConfigError as exc:
        return SubfinderOutcome(exit_code=None, failed=True, message=str(exc))

    timeout = settings.subfinder_timeout_seconds if timeout_seconds is None else timeout_seconds
    limit = settings.subfinder_max_output_bytes if max_output_bytes is None else max_output_bytes
    argv = [program, "-silent", "-d", domain]
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
    except OSError:
        return SubfinderOutcome(exit_code=None, failed=True, message="Subfinder could not be started.")

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
        _kill(proc)
    if overflow and proc.poll() is None:
        _kill(proc)
    for reader in readers:
        reader.join(timeout=5)

    if timed_out:
        return SubfinderOutcome(exit_code=None, timed_out=True, failed=True, message="Subfinder timed out.")
    if overflow:
        return SubfinderOutcome(
            exit_code=proc.returncode,
            too_large=True,
            failed=True,
            message="Subfinder output exceeded the size limit.",
        )

    stdout = stdout_box[0] if stdout_box else b""
    stderr = stderr_box[0] if stderr_box else b""
    note = sanitize_tool_text(stderr)
    if proc.returncode != 0:
        message = f"Subfinder exited with status {proc.returncode}."
        if note:
            message = f"{message} {note}"
        return SubfinderOutcome(exit_code=proc.returncode, failed=True, message=message[:500])
    return SubfinderOutcome(exit_code=0, hosts=parse_subfinder_hosts(stdout), message=note)
