"""Run OWASP ZAP as a passive baseline against origins the worker already chose.

The daemon binds to 127.0.0.1. This module does not call ZAP_API_URL.
Active scan, spider, and fuzzer actions are not requested.
"""
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from app.config import settings
from app.scanners.nuclei import normalize_target_url
from app.scanners.subfinder import sanitize_tool_text

_EXECUTABLE_NAME = {"zap.sh", "zap.bat", "zap"}
_UNSAFE_EXECUTABLE = set("\x00\n\r;&|$`<>\"'")
_BIND_HOST = "127.0.0.1"
_RISK = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class ZapConfigError(Exception):
    """ZAP_PATH is not the ZAP program."""


@dataclass
class ZapAlert:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    hostname: str
    evidence: str


@dataclass
class ZapOutcome:
    exit_code: int | None
    alerts: list[ZapAlert] = field(default_factory=list)
    invalid_records: int = 0
    message: str = ""
    timed_out: bool = False
    too_large: bool = False
    failed: bool = False


def zap_command(program: str, port: int) -> list[str] | str:
    """Build a foreground command. zap.sh backgrounds -daemon, so a real install runs java -jar."""
    path = Path(program)
    prefix = [program]
    if path.is_file() and path.name.lower() in {"zap.sh", "zap.bat"}:
        jars = sorted(path.parent.glob("zap-*.jar"))
        if len(jars) != 1:
            return "ZAP jar was not found next to zap.sh."
        prefix = ["java", "-jar", str(jars[0])]
    return prefix + [
        "-daemon",
        "-silent",
        "-host",
        _BIND_HOST,
        "-port",
        str(port),
        "-config",
        "api.disablekey=true",
        "-config",
        "api.addrs.addr.name=127.0.0.1",
        "-config",
        "api.addrs.addr.regex=false",
        "-config",
        "start.checkForUpdates=false",
    ]


def resolve_zap_executable(configured: str | None = None) -> str:
    text = (configured if configured is not None else settings.zap_path).strip()
    if not text:
        text = "zap.sh"
    if len(text) > 512 or any(char in _UNSAFE_EXECUTABLE for char in text):
        raise ZapConfigError("ZAP_PATH is not a single executable.")
    if os.path.basename(text).lower() not in _EXECUTABLE_NAME:
        raise ZapConfigError("ZAP_PATH must point at zap.sh.")
    return text


def _clean(value: str, limit: int = 240) -> str:
    text = sanitize_tool_text(str(value).encode("utf-8", errors="replace"))
    lowered = text.lower()
    if any(token in lowered for token in ("set-cookie", "authorization:", "bearer ", "password=")):
        return "[redacted]"
    return text[:limit]


def parse_zap_alerts(payload: object, allowed_hosts: set[str]) -> tuple[list[ZapAlert], int]:
    rows = payload.get("alerts") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return [], 1
    alerts = []
    invalid = 0
    seen = set()
    for item in rows:
        if not isinstance(item, dict):
            invalid += 1
            continue
        risk = _RISK.get(str(item.get("risk") or "").strip().lower())
        if risk is None:
            invalid += 1
            continue
        plugin_id = str(item.get("pluginId") or item.get("pluginid") or "").strip()
        if not plugin_id.isdigit() or len(plugin_id) > 10:
            invalid += 1
            continue
        raw_url = str(item.get("url") or "")
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or host not in allowed_hosts:
            invalid += 1
            continue
        expected = 443 if parsed.scheme == "https" else 80
        if parsed.port not in (None, expected) or parsed.query or parsed.username:
            invalid += 1
            continue
        path = parsed.path or "/"
        if ".." in path or len(path) > 200:
            invalid += 1
            continue
        url = f"{parsed.scheme}://{host}{path}"
        name = _clean(str(item.get("alert") or item.get("name") or plugin_id), 180) or plugin_id
        evidence = _clean(str(item.get("evidence") or name))
        confidence = _clean(str(item.get("confidence") or "Unknown"), 40) or "Unknown"
        key = (plugin_id, url)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(ZapAlert(plugin_id, name, risk, confidence, url, host, evidence))
    return alerts, invalid


def _local_get(base: str, route: str, limit: int) -> dict:
    parsed = urlparse(base)
    if parsed.hostname != _BIND_HOST:
        raise ZapConfigError("ZAP is only contacted on 127.0.0.1.")
    request = Request(base + route, method="GET")
    with urlopen(request, timeout=10) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ZapConfigError("ZAP output exceeded the size limit.")
    payload = json.loads(body.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ZapConfigError("ZAP returned a response that was not an object.")
    return payload


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_zap(
    urls: list[str],
    *,
    executable: str | None = None,
    job_timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
    transport=None,
) -> ZapOutcome:
    """Passive baseline for the given origins. The public ZAP setting is ignored."""
    chosen = []
    hosts = set()
    for url in urls:
        located = normalize_target_url(url)
        if located is None:
            continue
        canonical, host = located
        if canonical not in chosen:
            chosen.append(canonical)
            hosts.add(host)
    if not chosen:
        return ZapOutcome(exit_code=0, message="No origins to scan.")
    try:
        program = resolve_zap_executable(executable)
    except ZapConfigError as exc:
        return ZapOutcome(exit_code=None, failed=True, message=str(exc))
    port = int(settings.zap_bind_port)
    if port < 1 or port > 65535:
        return ZapOutcome(exit_code=None, failed=True, message="ZAP bind port is not valid.")
    base = f"http://{_BIND_HOST}:{port}"
    argv = zap_command(program, port)
    if isinstance(argv, str):
        return ZapOutcome(exit_code=None, failed=True, message=argv)
    fetch = transport or (lambda route: _local_get(base, route, settings.zap_max_output_bytes if max_output_bytes is None else max_output_bytes))
    proc = None
    if transport is None:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        except OSError:
            return ZapOutcome(exit_code=None, failed=True, message="ZAP could not be started.")
    timeout = settings.zap_job_timeout_seconds if job_timeout_seconds is None else job_timeout_seconds
    try:
        started = time.monotonic()
        ready = False
        while time.monotonic() - started < timeout:
            try:
                fetch("/JSON/core/view/version/")
                ready = True
                break
            except Exception:
                if proc is not None and proc.poll() is not None:
                    return ZapOutcome(exit_code=proc.returncode, failed=True, message="ZAP exited before it was ready.")
                time.sleep(0.2)
        if not ready:
            return ZapOutcome(exit_code=None, timed_out=True, failed=True, message="ZAP timed out.")
        fetch("/JSON/pscan/action/setScanOnlyInScope/?onlyInScope=true")
        for url in chosen:
            fetch("/JSON/core/action/accessUrl/?url=" + quote(url + "/", safe="") + "&followRedirects=false")
        raw = fetch("/JSON/alert/view/alerts/?start=0&count=" + str(int(settings.zap_max_alerts)))
        alerts_body = raw.get("alerts") if isinstance(raw, dict) else None
        # Some ZAP views wrap the list one level down.
        if isinstance(raw, dict) and isinstance(raw.get("alerts"), list):
            parsed_input = raw
        elif isinstance(alerts_body, dict):
            parsed_input = alerts_body
        else:
            parsed_input = raw
        alerts, invalid = parse_zap_alerts(parsed_input, hosts)
        return ZapOutcome(exit_code=0, alerts=alerts, invalid_records=invalid)
    except ZapConfigError as exc:
        return ZapOutcome(exit_code=None, failed=True, message=str(exc))
    except Exception:
        return ZapOutcome(exit_code=None, failed=True, message="ZAP did not return a passive baseline.")
    finally:
        if proc is not None:
            try:
                fetch("/JSON/core/action/shutdown/")
            except Exception:
                pass
            _kill(proc)
