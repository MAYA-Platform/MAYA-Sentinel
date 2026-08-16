from __future__ import annotations

import argparse
import io
import json
import mimetypes
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
WEB = ROOT / "web"
DATA = ROOT / "data"
REPORTS = ROOT / "reports" / "public-v0.2"
HISTORY = DATA / "scan_history_public_v0_2.json"
HOST = "127.0.0.1"
PORT = 5182
VERSION = "1.0.0"

MAX_UPLOAD_BYTES = 80 * 1024 * 1024
MAX_MULTIPART_PARTS = 8
MAX_PART_HEADER_BYTES = 16 * 1024
MAX_FIELD_NAME_BYTES = 128
MAX_FILENAME_BYTES = 255
READ_CHUNK_BYTES = 1024 * 1024
SOCKET_READ_TIMEOUT_SECONDS = 20
SCAN_DEADLINE_SECONDS = 180
SESSION_TOKEN = secrets.token_urlsafe(32)
_ACTIVE_PORT = PORT
_SCAN_LOCK = threading.Lock()

sys.path.insert(0, str(SRC))

from maya_lens.public_safety import PUBLIC_BLOCKED, build_public_projection
from maya_lens.report import write_reports
from maya_lens.retention import RetainedScanHistory, history_record, validate_scan_id
from maya_lens.scanner import scan_zip
from maya_lens.universal_scan import universal_scan


class RequestRejected(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message


def retained_history() -> RetainedScanHistory:
    return RetainedScanHistory(HISTORY, REPORTS)


def json_bytes(payload: dict[str, Any], status: int = 200) -> tuple[int, bytes, str]:
    return status, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8"


def public_error(code: str, message: str, status: int = 400, **extra: Any) -> tuple[int, bytes, str]:
    payload = {"ok": False, "error": {"code": code, "message": message}}
    payload.update(extra)
    return json_bytes(payload, status)


def _split_header_values(values: list[str]) -> list[str]:
    split: list[str] = []
    for value in values:
        split.extend(part.strip() for part in str(value).split(",") if part.strip())
    return split


def validated_content_length(headers: Any) -> int:
    values = _split_header_values(list(headers.get_all("Content-Length", [])) if hasattr(headers, "get_all") else [])
    if not values:
        raise RequestRejected(411, "content_length_required", "Content-Length is required for bounded uploads.")
    if len(set(values)) > 1:
        raise RequestRejected(400, "conflicting_content_length", "Conflicting Content-Length headers are not accepted.")
    raw = values[0]
    try:
        length = int(raw)
    except ValueError as exc:
        raise RequestRejected(400, "malformed_content_length", "Content-Length must be a non-negative integer.") from exc
    if str(length) != raw.strip() or length < 0:
        raise RequestRejected(400, "malformed_content_length", "Content-Length must be a non-negative integer.")
    if length > MAX_UPLOAD_BYTES:
        raise RequestRejected(413, "upload_too_large", "Repo ZIP uploads must stay under the configured local limit.")
    return length


def _observable_extra_bytes(stream: Any) -> bool:
    if isinstance(stream, io.BytesIO):
        return stream.tell() < len(stream.getbuffer())
    return False


def read_bounded_body(stream: Any, length: int) -> bytes:
    remaining = length
    chunks: list[bytes] = []
    while remaining:
        chunk = stream.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise RequestRejected(400, "truncated_body", "Upload body ended before Content-Length bytes were received.")
        chunks.append(chunk)
        remaining -= len(chunk)
    if _observable_extra_bytes(stream):
        raise RequestRejected(413, "body_exceeds_content_length", "Upload body exceeded the declared Content-Length.")
    return b"".join(chunks)


def parse_multipart_upload(content_type: str, body: bytes) -> tuple[str, bytes]:
    if not content_type.lower().startswith("multipart/form-data"):
        raise RequestRejected(415, "wrong_content_type", "Upload must use multipart/form-data.")
    if "boundary=" not in content_type.lower():
        raise RequestRejected(400, "missing_multipart_boundary", "Multipart upload is missing its boundary.")
    envelope = (
        f"Content-Type: {content_type}\r\n"
        "MIME-Version: 1.0\r\n\r\n"
    ).encode("utf-8") + body
    try:
        message = BytesParser(policy=policy.default).parsebytes(envelope)
    except Exception as exc:
        raise RequestRejected(400, "malformed_multipart", "Multipart upload could not be parsed.") from exc
    if not message.is_multipart():
        raise RequestRejected(400, "malformed_multipart", "Multipart upload could not be parsed.")

    parts = list(message.iter_parts())
    if not parts:
        raise RequestRejected(400, "missing_zipfile", "Missing zipfile upload.")
    if len(parts) > MAX_MULTIPART_PARTS:
        raise RequestRejected(413, "too_many_multipart_parts", "Multipart upload has too many parts.")

    zip_payload: tuple[str, bytes] | None = None
    for part in parts:
        header_bytes = sum(len(str(key).encode("utf-8")) + len(str(value).encode("utf-8")) for key, value in part.items())
        if header_bytes > MAX_PART_HEADER_BYTES:
            raise RequestRejected(413, "multipart_headers_too_large", "Multipart part headers exceed the local limit.")
        field_name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        if field_name and len(str(field_name).encode("utf-8")) > MAX_FIELD_NAME_BYTES:
            raise RequestRejected(413, "field_name_too_large", "Multipart field name exceeds the local limit.")
        if filename and len(str(filename).encode("utf-8")) > MAX_FILENAME_BYTES:
            raise RequestRejected(413, "filename_too_large", "Upload filename exceeds the local limit.")
        payload = part.get_payload(decode=True)
        if payload is None:
            payload_text = part.get_content()
            payload = payload_text.encode("utf-8") if isinstance(payload_text, str) else bytes(payload_text)
        if len(payload) > MAX_UPLOAD_BYTES:
            raise RequestRejected(413, "upload_too_large", "Repo ZIP uploads must stay under the configured local limit.")
        if field_name == "zipfile":
            if zip_payload is not None:
                raise RequestRejected(400, "duplicate_zipfile", "Only one zipfile upload is accepted.")
            if not filename:
                raise RequestRejected(400, "missing_filename", "Missing upload filename.")
            zip_payload = (Path(str(filename)).name or "repo.zip", bytes(payload))
    if zip_payload is None:
        raise RequestRejected(400, "missing_zipfile", "Missing zipfile upload.")
    return zip_payload


def _parse_host_port(host_header: str | None) -> tuple[str, int] | None:
    if not host_header:
        return None
    host = host_header.rsplit("@", 1)[-1].strip().lower()
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            return None
        hostname = host[1:end]
        rest = host[end + 1:]
        if not rest.startswith(":"):
            return None
        port_text = rest[1:]
    else:
        if host.count(":") != 1:
            return None
        hostname, port_text = host.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return None
    return hostname, port


def _host_allowed(host_header: str | None, *, require_present: bool = False) -> bool:
    parsed = _parse_host_port(host_header)
    if parsed is None:
        return not require_present
    hostname, port = parsed
    return hostname in {"127.0.0.1", "localhost", "::1"} and port == _ACTIVE_PORT


def _origin_allowed(origin_header: str | None, *, require_present: bool = False) -> bool:
    if not origin_header:
        return not require_present
    try:
        parsed = urllib.parse.urlsplit(origin_header)
    except ValueError:
        return False
    port = parsed.port
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"} and port == _ACTIVE_PORT


def _safe_report_path(name: str) -> Path:
    clean = urllib.parse.unquote(name)
    if Path(clean).name != clean or "/" in clean or "\\" in clean:
        raise RequestRejected(404, "not_found", "Not found.")
    root = REPORTS.resolve()
    target = (root / clean).resolve()
    if root not in target.parents and target != root:
        raise RequestRejected(404, "not_found", "Not found.")
    return target


class MayaLensHandler(BaseHTTPRequestHandler):
    server_version = "MAYARepoBrief/0.2"

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, body: bytes, content_type: str, *, set_session: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "bluetooth=(), camera=(), geolocation=(), microphone=(), payment=(), serial=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, rejection: RequestRejected) -> None:
        status, body, ctype = public_error(rejection.code, rejection.message, rejection.status)
        self._send(status, body, ctype)

    def _validate_request_source(self, *, mutating: bool = False) -> None:
        if not _host_allowed(self.headers.get("Host"), require_present=mutating):
            raise RequestRejected(403, "invalid_host", "Request host is not accepted by this local server.")
        if not _origin_allowed(self.headers.get("Origin"), require_present=mutating):
            raise RequestRejected(403, "invalid_origin", "Request origin is not accepted by this local server.")

    def _require_token(self) -> None:
        header_token = self.headers.get("X-MAYA-Session-Token", "")
        if not secrets.compare_digest(header_token, SESSION_TOKEN):
            raise RequestRejected(403, "invalid_session_token", "A valid local session token is required.")

    def do_GET(self):
        try:
            self._validate_request_source()
            path = self.path.split("?", 1)[0]
            if path == "/api/health":
                status, body, ctype = json_bytes({"app": "maya-sentinel", "version": VERSION, "status": "ok"})
                return self._send(status, body, ctype)
            if path == "/api/session":
                status, body, ctype = json_bytes({"ok": True, "app": "maya-sentinel", "version": VERSION, "token": SESSION_TOKEN})
                return self._send(status, body, ctype)
            if path == "/api/history":
                status, body, ctype = json_bytes({"ok": True, "items": retained_history().list()})
                return self._send(status, body, ctype)
            if path.startswith("/reports/"):
                target = _safe_report_path(path.removeprefix("/reports/"))
                if not target.exists() or not target.is_file():
                    raise RequestRejected(404, "not_found", "Not found.")
                ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
                return self._send(200, target.read_bytes(), ctype)
            if path in ("/", "/index.html"):
                target = WEB / "index.html"
                set_session = False
            else:
                target = WEB / path.lstrip("/")
                set_session = False
            resolved = target.resolve()
            web_root = WEB.resolve()
            if not target.exists() or not target.is_file() or (web_root not in resolved.parents and resolved != web_root):
                raise RequestRejected(404, "not_found", "Not found.")
            ctype = mimetypes.guess_type(str(target))[0] or "text/plain"
            return self._send(200, target.read_bytes(), ctype, set_session=set_session)
        except RequestRejected as rejection:
            return self._send_error(rejection)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/scan":
            status, body, ctype = public_error("not_found", "Not found.", 404)
            return self._send(status, body, ctype)
        try:
            content_length = validated_content_length(self.headers)
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("multipart/form-data"):
                raise RequestRejected(415, "wrong_content_type", "Upload must use multipart/form-data.")
            self._validate_request_source(mutating=True)
            self._require_token()
            body = read_bounded_body(self.rfile, content_length)
            filename, payload = parse_multipart_upload(content_type, body)
            if not _SCAN_LOCK.acquire(blocking=False):
                raise RequestRejected(429, "scan_busy", "Another local scan is already running.")
            try:
                return self._scan_payload(filename, payload)
            finally:
                _SCAN_LOCK.release()
        except RequestRejected as rejection:
            return self._send_error(rejection)

    def _scan_payload(self, filename: str, payload: bytes) -> None:
        started = time.monotonic()
        upload_root = HISTORY.parent / "tmp_uploads"
        upload_root.mkdir(parents=True, exist_ok=True)
        tmp_path = upload_root / f"maya_lens_upload_{secrets.token_hex(12)}"
        tmp_path.mkdir(parents=False, exist_ok=False)
        try:
            upload = tmp_path / Path(filename).name
            upload.write_bytes(payload)
            try:
                result = scan_zip(upload, work_root=tmp_path / "work", deadline_seconds=SCAN_DEADLINE_SECONDS)
                public_result = build_public_projection(result)
                reports = write_reports(public_result, REPORTS)
                public_result["reports"] = build_public_projection({"reports": reports}).get("reports", {})
                retained_history().append(history_record(public_result, reports))
                if time.monotonic() - started > SCAN_DEADLINE_SECONDS:
                    status, body, ctype = public_error("scan_deadline_exceeded", "Scan exceeded the local deadline.", 504)
                elif public_result.get("status") == PUBLIC_BLOCKED:
                    status, body, ctype = public_error(
                        "zip_intake_blocked",
                        "ZIP intake was blocked during guarded intake before static analysis.",
                        400,
                        blocked=True,
                        result=public_result,
                    )
                else:
                    status, body, ctype = json_bytes({"ok": True, "result": public_result})
            except Exception:
                status, body, ctype = public_error("scan_failed", "Scan failed before a public receipt could be completed.", 500)
            return self._send(status, body, ctype)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    def do_DELETE(self):
        try:
            self._validate_request_source(mutating=True)
            self._require_token()
            path = self.path.split("?", 1)[0]
            if path == "/api/history":
                status, body, ctype = json_bytes({"ok": True, "result": retained_history().clear()})
                return self._send(status, body, ctype)
            if path.startswith("/api/history/"):
                scan_id = validate_scan_id(urllib.parse.unquote(path.removeprefix("/api/history/")))
                status, body, ctype = json_bytes({"ok": True, "result": retained_history().delete_one(scan_id)})
                return self._send(status, body, ctype)
            raise RequestRejected(404, "not_found", "Not found.")
        except ValueError:
            status, body, ctype = public_error("invalid_scan_id", "Scan ID is not valid.", 400)
            return self._send(status, body, ctype)
        except RequestRejected as rejection:
            return self._send_error(rejection)


def server_alive(port: int = PORT) -> bool:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/health", timeout=1.5) as resp:
            if resp.status != 200 or json.loads(resp.read().decode("utf-8")) != {"app": "maya-sentinel", "version": VERSION, "status": "ok"}:
                return False
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/session", timeout=1.5) as resp:
            headers = {key.lower(): value for key, value in resp.headers.items()}
            payload = json.loads(resp.read().decode("utf-8"))
            token = payload.get("token")
            return (
                resp.status == 200
                and headers.get("set-cookie") is None
                and payload.get("ok") is True
                and payload.get("app") == "maya-sentinel"
                and payload.get("version") == VERSION
                and isinstance(token, str)
                and len(token) >= 32
            )
    except Exception:
        return False


def open_ui(port: int | None = None) -> None:
    webbrowser.open(f"http://{HOST}:{port or _ACTIVE_PORT}/")


def _make_server(preferred_port: int = PORT) -> ThreadingHTTPServer:
    global _ACTIVE_PORT
    try:
        httpd = ThreadingHTTPServer((HOST, preferred_port), MayaLensHandler)
        _ACTIVE_PORT = preferred_port
        return httpd
    except OSError as exc:
        if getattr(exc, "winerror", None) != 10048 and getattr(exc, "errno", None) not in {48, 98}:
            raise RuntimeError("Could not start local MAYA Sentinel server.") from exc
    try:
        httpd = ThreadingHTTPServer((HOST, 0), MayaLensHandler)
        _ACTIVE_PORT = int(httpd.server_address[1])
        return httpd
    except OSError as exc:
        raise RuntimeError("Could not start local MAYA Sentinel server on a loopback port.") from exc


def run_server(open_browser: bool = True) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    httpd = _make_server(PORT)
    httpd.timeout = SOCKET_READ_TIMEOUT_SECONDS
    try:
        httpd.socket.settimeout(SOCKET_READ_TIMEOUT_SECONDS)
    except socket.error:
        pass
    if open_browser:
        threading.Timer(0.6, lambda: open_ui(_ACTIVE_PORT)).start()
    print(f"MAYA Sentinel v{VERSION} running at http://{HOST}:{_ACTIVE_PORT}/")
    httpd.serve_forever()


MODE_PROJECTIONS = {
    "safety": {
        "label": "Safety Scan",
        "axes": ["Risk Surface", "Credential Exposure", "Binary Surface", "Filesystem Surface", "Install Observations"],
        "categories": {"credential", "binary", "install_hook", "filesystem", "process", "archive_safety", "obfuscation"},
    },
    "phishing": {
        "label": "Phishing / Impersonation",
        "axes": ["Phishing Surface", "Risk Surface", "Network Surface"],
        "categories": {"phishing", "network", "intrusiveness"},
    },
    "supply-chain": {
        "label": "Dependency & Supply Chain",
        "axes": ["Dependency Risk", "Install Observations", "Risk Surface"],
        "categories": {"dependency", "install_hook", "credential"},
    },
    "ai-surface": {
        "label": "AI / Agent Surface",
        "axes": ["Risk Surface"],
        "categories": {"agentic_attack"},
    },
    "exfil": {
        "label": "Exfil & Telemetry",
        "axes": ["Phishing Surface", "Intrusiveness", "Network Surface"],
        "categories": {"phishing", "intrusiveness", "network"},
    },
    "archive": {
        "label": "Archive Safety",
        "axes": ["Archive Safety", "Storage Footprint", "Binary Surface"],
        "categories": {"archive_safety", "binary"},
    },
}


def apply_mode_projection(result: dict[str, Any], mode: str) -> dict[str, Any]:
    """Reorder/filter a scan result to lead with a chosen scan focus.

    Same mode set as the web UI. The full scan data stays intact in the
    result; only presentation order (axes) and the lead findings list are
    projected. Mode 'safety' returns the result unchanged.
    """
    projection = MODE_PROJECTIONS.get(mode or "safety")
    if not projection or mode == "safety":
        return result
    axes = result.get("axes", {})
    entries = list(axes.items())
    preferred = [item for name in projection["axes"] for item in entries if item[0] == name]
    rest = [item for item in entries if item[0] not in projection["axes"]]
    result = dict(result)
    result["axes"] = dict(preferred + rest)
    findings = result.get("findings", [])
    if projection["categories"]:
        result["findings"] = [f for f in findings if f.get("category") in projection["categories"]]
    result["mode"] = {"id": mode, "label": projection["label"]}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=f"MAYA Sentinel v{VERSION} local repo ZIP scanner")
    parser.add_argument("--scan", help="Scan a ZIP from the command line and print public-safe JSON")
    parser.add_argument("--mode", default="safety", choices=["safety", "phishing", "supply-chain", "ai-surface", "exfil", "archive"],
                        help="Report focus: safety (default), phishing, supply-chain, ai-surface, exfil, archive")
    parser.add_argument("--no-browser", action="store_true", help="Start server without opening browser")
    args = parser.parse_args()
    if args.scan:
        scan_path = Path(args.scan)
        if not scan_path.exists():
            print(f"MAYA Sentinel error: scan target not found: {scan_path}", file=sys.stderr)
            return 2
        result = build_public_projection(universal_scan(scan_path))
        if not result.get("disclaimer"):
            print("MAYA Sentinel error: scan produced an incomplete result; no report written.", file=sys.stderr)
            return 2
        result = apply_mode_projection(result, args.mode)
        reports = write_reports(result, REPORTS)
        result["reports"] = build_public_projection({"reports": reports}).get("reports", {})
        retained_history().append(history_record(result, reports))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if server_alive(PORT):
        if not args.no_browser:
            open_ui(PORT)
        return 0
    try:
        run_server(open_browser=not args.no_browser)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
