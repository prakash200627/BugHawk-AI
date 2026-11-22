"""Run ProjectDiscovery httpx against hostnames the worker already chose.

Arguments are a fixed list. Ports are only 80 and 443. Redirects are not followed.
"""
import json
import re
import subprocess
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.config import settings
from app.scanners.subfinder import is_safe_domain, sanitize_tool_text

_EXECUTABLE_NAME = {"httpx", "httpx.exe"}
_UNSAFE_EXECUTABLE = set("\x00\n\r;&|$`<>\"'")
ALLOWED_PORTS = (80, 443)
_PRIVATE_IP = (
    r"(?:^|\b)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})(?:\b|$)"
)


class HttpxConfigError(Exception):
    """HTTPX_PATH is not the httpx program."""


@dataclass
class HttpxProbe:
    hostname: str
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: list[str] = field(default_factory=list)


@dataclass
class HttpxOutcome:
    exit_code: int | None
    probes: list[HttpxProbe] = field(default_factory=list)
    invalid_lines: int = 0
    message: str = ""
    timed_out: bool = False
    too_large: bool = False
    failed: bool = False


def resolve_httpx_executable(configured: str | None = None) -> str:
    """Use HTTPX_PATH only when it names the httpx program."""
    text = (configured if configured is not None else settings.httpx_path).strip()
    if not text:
        text = "httpx"
    if len(text) > 512 or any(char in _UNSAFE_EXECUTABLE for char in text):
        raise HttpxConfigError("HTTPX_PATH is not a single executable.")
    if text.replace("\\", "/").rsplit("/", 1)[-1].lower() not in _EXECUTABLE_NAME:
        raise HttpxConfigError("HTTPX_PATH must point at the httpx program.")
    return text


def _clean_text(value: str, limit: int) -> str:
    text = sanitize_tool_text(value.encode("utf-8", errors="replace"))
    text = re.sub(_PRIVATE_IP, "[redacted]", text)
    return text[:limit].strip()


def _host_of(url: str) -> str | None:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        return None
    port = parsed.port
    expected = 443 if parsed.scheme == "https" else 80
    if port not in (None, expected) or (port is not None and port not in ALLOWED_PORTS):
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not is_safe_domain(host):
        return None
    return host


def _redirect_stays(item: dict, host: str) -> bool:
    """Reject a result that names a different host in a redirect field."""
    for key in ("final_url", "location", "redirect_url"):
        raw = item.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        if raw.startswith("/"):
            continue
        other = _host_of(raw) if "://" in raw else None
        if other is None or other != host:
            return False
    return True


def parse_httpx_line(line: str, allowed_hosts: set[str]) -> HttpxProbe | None:
    """Keep one JSON object only when its URL host was requested and is in scope."""
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(item, dict):
        return None
    url = item.get("url")
    if not isinstance(url, str):
        return None
    host = _host_of(url)
    if host is None or host not in allowed_hosts or not _redirect_stays(item, host):
        return None
    probe = HttpxProbe(hostname=host, url=url.split("?", 1)[0])
    status = item.get("status_code", item.get("status-code"))
    if isinstance(status, int) and 100 <= status <= 599:
        probe.status_code = status
    title = item.get("title")
    if isinstance(title, str) and title.strip():
        probe.title = _clean_text(title, 200) or None
    server = item.get("webserver")
    if isinstance(server, str) and server.strip():
        probe.webserver = _clean_text(server, 80) or None
    tech = item.get("tech")
    if isinstance(tech, list):
        seen: list[str] = []
        for entry in tech:
            if not isinstance(entry, str):
                continue
            cleaned = _clean_text(entry, 40)
            if cleaned and cleaned not in seen:
                seen.append(cleaned)
            if len(seen) == 20:
                break
        probe.technologies = seen
    return probe


def parse_httpx_output(stdout: bytes, allowed_hosts: set[str]) -> tuple[list[HttpxProbe], int]:
    probes: list[HttpxProbe] = []
    seen: set[tuple[str, str]] = set()
    invalid = 0
    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        probe = parse_httpx_line(line, allowed_hosts)
        if probe is None:
            invalid += 1
            continue
        key = (probe.hostname, probe.url)
        if key in seen:
            continue
        seen.add(key)
        probes.append(probe)
    return probes, invalid


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


def probe_urls(hosts: list[str]) -> list[str]:
    """HTTPS and HTTP on the allowlisted ports, deduped, in input order."""
    urls: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if not is_safe_domain(host):
            continue
        for url in (f"https://{host}", f"http://{host}"):
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def run_httpx(
    hosts: list[str],
    *,
    executable: str | None = None,
    timeout_seconds: int | None = None,
    job_timeout_seconds: int | None = None,
    threads: int | None = None,
    max_output_bytes: int | None = None,
) -> HttpxOutcome:
    """Probe the given hostnames. The host list is not taken from the API body."""
    allowed = [host for host in dict.fromkeys(hosts) if is_safe_domain(host)]
    if not allowed:
        return HttpxOutcome(exit_code=0, message="No hostnames to probe.")
    try:
        program = resolve_httpx_executable(executable)
    except HttpxConfigError as exc:
        return HttpxOutcome(exit_code=None, failed=True, message=str(exc))

    request_timeout = settings.httpx_timeout_seconds if timeout_seconds is None else timeout_seconds
    job_timeout = settings.httpx_job_timeout_seconds if job_timeout_seconds is None else job_timeout_seconds
    worker_threads = settings.httpx_threads if threads is None else threads
    worker_threads = min(10, max(1, int(worker_threads)))
    limit = settings.httpx_max_output_bytes if max_output_bytes is None else max_output_bytes
    urls = probe_urls(allowed)
    argv = [
        program,
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-web-server",
        "-status-code",
        "-timeout",
        str(int(request_timeout)),
        "-threads",
        str(worker_threads),
        "-ports",
        "80,443",
        "-no-fallback",
    ]
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError:
        return HttpxOutcome(exit_code=None, failed=True, message="httpx could not be started.")

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
        return HttpxOutcome(exit_code=None, timed_out=True, failed=True, message="httpx timed out.")
    if overflow:
        return HttpxOutcome(
            exit_code=proc.returncode,
            too_large=True,
            failed=True,
            message="httpx output exceeded the size limit.",
        )
    stdout = stdout_box[0] if stdout_box else b""
    stderr = stderr_box[0] if stderr_box else b""
    note = sanitize_tool_text(stderr)
    probes, invalid = parse_httpx_output(stdout, set(allowed))
    if proc.returncode != 0:
        message = f"httpx exited with status {proc.returncode}."
        if note:
            message = f"{message} {note}"
        return HttpxOutcome(
            exit_code=proc.returncode,
            probes=probes,
            invalid_lines=invalid,
            failed=True,
            message=message[:500],
        )
    return HttpxOutcome(exit_code=0, probes=probes, invalid_lines=invalid, message=note)
