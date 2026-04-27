#!/usr/bin/env python3
import argparse
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

DEFAULT_RULES_PATH = "/workspace/config/rules/local.rules"
DEFAULT_RULES_ROOT = "/workspace/config/rules"
DEFAULT_ALERT_PATH = "/var/log/minisnort/alert.log"
DEFAULT_STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = 128 * 1024
ALERT_READ_BYTES = 64 * 1024
RULE_SAVE_LOCK = threading.Lock()
RULE_HEADER_RE = re.compile(
    r"^(alert|drop|pass|log)\s+(ip|tcp|udp|icmp)\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s*\((.*)\)\s*$",
    re.IGNORECASE,
)
SID_RE = re.compile(r"(?:^|;)\s*sid\s*:\s*([1-9][0-9]*)\s*(?:;|$)")
MSG_RE = re.compile(r"(?:^|;)\s*msg\s*:\s*\"[^\"]*\"\s*(?:;|$)")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def confined_path(file_path: str, root_path: str) -> Path:
    root = Path(root_path).resolve()
    path = Path(file_path).resolve()
    path.relative_to(root)
    return path


def read_alerts(alert_path: str, since: int) -> dict[str, object]:
    path = Path(alert_path)
    if since < 0:
        since = 0
    if not path.exists():
        return {"offset": 0, "lines": [], "exists": False}
    size = path.stat().st_size
    if since > size:
        since = 0
    with path.open("rb") as handle:
        handle.seek(since)
        data = handle.read(ALERT_READ_BYTES)
    if data and not data.endswith(b"\n"):
        newline_index = data.rfind(b"\n")
        if newline_index == -1:
            return {"offset": since, "lines": [], "exists": True, "size": size}
        offset = since + newline_index + 1
        data = data[: offset - since]
    else:
        offset = since + len(data)
    text = data.decode("utf-8", errors="replace")
    return {"offset": offset, "lines": text.splitlines(), "exists": True, "size": size}


def validate_rules(text: str) -> list[str]:
    errors: list[str] = []
    seen_sids: set[str] = set()
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = RULE_HEADER_RE.match(line)
        if not match:
            errors.append(f"line {line_no}: invalid rule header or options")
            continue
        options = match.group(3)
        if not options.rstrip().endswith(";"):
            errors.append(f"line {line_no}: options must end with ';'")
        if not MSG_RE.search(options):
            errors.append(f"line {line_no}: missing msg option")
        sid_match = SID_RE.search(options)
        if not sid_match:
            errors.append(f"line {line_no}: missing positive sid option")
            continue
        sid = sid_match.group(1)
        if sid in seen_sids:
            errors.append(f"line {line_no}: duplicate sid {sid}")
        seen_sids.add(sid)
    if not seen_sids:
        errors.append("rules file must contain at least one active rule")
    return errors


def backup_path_for(path: Path) -> Path:
    while True:
        backup = path.with_name(f"{path.name}.{utc_stamp()}.{secrets.token_hex(4)}.bak")
        try:
            with backup.open("xb"):
                return backup
        except FileExistsError:
            continue


def save_rules(rules_path: str, rules_root: str, text: str) -> Path:
    with RULE_SAVE_LOCK:
        path = confined_path(rules_path, rules_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = backup_path_for(path)
            shutil.copy2(path, backup)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                if text and not text.endswith("\n"):
                    handle.write("\n")
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise
        return path


class DashboardHandler(SimpleHTTPRequestHandler):
    server_version = "MiniSnortDashboard/1.0"

    def __init__(
        self,
        *args: Any,
        static_dir: str | Path | None = None,
        rules_path: str | None = None,
        rules_root: str | None = None,
        alert_path: str | None = None,
        write_token: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.static_dir = Path(static_dir or DEFAULT_STATIC_DIR)
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules_root = rules_root or DEFAULT_RULES_ROOT
        self.alert_path = alert_path or DEFAULT_ALERT_PATH
        self.write_token = write_token or ""
        super().__init__(*args, directory=str(self.static_dir), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def has_valid_write_token(self) -> bool:
        provided = self.headers.get("X-Dashboard-Token", "")
        return bool(self.write_token) and hmac.compare_digest(provided, self.write_token)

    def send_confined_rules_path_error(self) -> None:
        self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "rules path outside configured root"})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            try:
                rules = confined_path(self.rules_path, self.rules_root)
                alerts = Path(self.alert_path)
                payload = {
                    "rulesPath": str(rules),
                    "rulesExists": rules.exists(),
                    "rulesSize": rules.stat().st_size if rules.exists() else 0,
                    "alertPath": str(alerts),
                    "alertExists": alerts.exists(),
                    "alertSize": alerts.stat().st_size if alerts.exists() else 0,
                    "writeTokenRequired": True,
                }
            except ValueError:
                self.send_confined_rules_path_error()
                return
            except OSError:
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "unable to read dashboard status"})
                return
            self.send_json(HTTPStatus.OK, payload)
            return
        if parsed.path == "/api/alerts":
            query = parse_qs(parsed.query)
            raw_since = query.get("since", ["0"])[0]
            try:
                since = int(raw_since)
            except ValueError:
                since = 0
            try:
                self.send_json(HTTPStatus.OK, read_alerts(self.alert_path, since))
            except OSError:
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "unable to read alert log"})
            return
        if parsed.path == "/api/rules":
            try:
                path = confined_path(self.rules_path, self.rules_root)
                if not path.exists():
                    self.send_json(HTTPStatus.NOT_FOUND, {"error": "rules file not found"})
                    return
                payload = {"rules": path.read_text(encoding="utf-8"), "path": str(path)}
            except ValueError:
                self.send_confined_rules_path_error()
                return
            except OSError:
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "unable to read rules file"})
                return
            self.send_json(HTTPStatus.OK, payload)
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/rules":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self.has_valid_write_token():
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "invalid dashboard write token"})
            return
        length = self.headers.get("Content-Length")
        try:
            body_len = int(length or "0")
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid content length"})
            return
        if body_len <= 0 or body_len > MAX_BODY_BYTES:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid rule payload size"})
            return
        raw = self.rfile.read(body_len)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "rule payload must be valid utf-8"})
            return
        errors = validate_rules(text)
        if errors:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "rule validation failed", "details": errors})
            return
        try:
            saved_path = save_rules(self.rules_path, self.rules_root, text)
        except ValueError:
            self.send_confined_rules_path_error()
            return
        except OSError:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "unable to save rules file"})
            return
        self.send_json(HTTPStatus.OK, {"ok": True, "path": str(saved_path)})


def make_handler(
    static_dir: str,
    rules_path: str,
    rules_root: str,
    alert_path: str,
    write_token: str,
) -> Callable[..., DashboardHandler]:
    def factory(*args: Any, **kwargs: Any) -> DashboardHandler:
        return DashboardHandler(
            *args,
            static_dir=static_dir,
            rules_path=rules_path,
            rules_root=rules_root,
            alert_path=alert_path,
            write_token=write_token,
            **kwargs,
        )

    return factory


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--rules", default=os.environ.get("MINISNORT_RULES", DEFAULT_RULES_PATH))
    parser.add_argument("--rules-root", default=os.environ.get("MINISNORT_RULES_ROOT", DEFAULT_RULES_ROOT))
    parser.add_argument("--alerts", default=os.environ.get("MINISNORT_ALERTS", DEFAULT_ALERT_PATH))
    parser.add_argument("--static", default=str(DEFAULT_STATIC_DIR))
    args = parser.parse_args()

    write_token = os.environ.get("DASHBOARD_WRITE_TOKEN") or secrets.token_urlsafe(32)
    token_path = Path(os.environ.get("DASHBOARD_TOKEN_FILE", "/tmp/minisnort-dashboard-token"))
    token_path.write_text(write_token, encoding="utf-8")
    token_path.chmod(0o600)

    server = ThreadingHTTPServer(
        (args.host, args.port),
        make_handler(args.static, args.rules, args.rules_root, args.alerts, write_token),
    )
    print(f"dashboard listening on http://{args.host}:{args.port}", flush=True)
    print(f"dashboard write token file: {token_path}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
