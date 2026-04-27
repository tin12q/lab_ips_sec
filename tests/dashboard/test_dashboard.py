import json
import tempfile
import unittest
from http import HTTPStatus
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from dashboard.server import make_handler, read_alerts, save_rules, validate_rules


VALID_RULE = 'alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)\n'


class DashboardFunctionTests(unittest.TestCase):
    def test_read_alerts_returns_lines_after_offset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            alert_path = Path(temp_dir) / "alert.log"
            alert_path.write_text("one\ntwo\n", encoding="utf-8")

            result = read_alerts(str(alert_path), 4)

            self.assertTrue(result["exists"])
            self.assertEqual(result["lines"], ["two"])
            self.assertEqual(result["offset"], alert_path.stat().st_size)

    def test_read_alerts_holds_partial_line_offset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            alert_path = Path(temp_dir) / "alert.log"
            alert_path.write_text("complete\npartial", encoding="utf-8")

            result = read_alerts(str(alert_path), 0)

            self.assertEqual(result["lines"], ["complete"])
            self.assertEqual(result["offset"], len("complete\n"))

    def test_read_alerts_resets_offset_when_file_truncates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            alert_path = Path(temp_dir) / "alert.log"
            alert_path.write_text("new\n", encoding="utf-8")

            result = read_alerts(str(alert_path), 99)

            self.assertEqual(result["lines"], ["new"])

    def test_validate_rules_rejects_duplicate_sid(self):
        errors = validate_rules(
            'alert icmp any any -> any any (msg:"one"; sid:1;)\n'
            'alert icmp any any -> any any (msg:"two"; sid:1;)\n'
        )

        self.assertIn("line 2: duplicate sid 1", errors)

    def test_save_rules_creates_backup_and_normalizes_newline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rules_path = root / "local.rules"
            rules_path.write_text(VALID_RULE, encoding="utf-8")

            save_rules(str(rules_path), str(root), VALID_RULE.rstrip("\n"))

            self.assertEqual(rules_path.read_text(encoding="utf-8"), VALID_RULE)
            self.assertEqual(len(list(root.glob("local.rules.*.bak"))), 1)

    def test_save_rules_keeps_unique_rapid_backups(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rules_path = root / "local.rules"
            rules_path.write_text(VALID_RULE, encoding="utf-8")

            save_rules(str(rules_path), str(root), VALID_RULE)
            save_rules(str(rules_path), str(root), VALID_RULE)

            self.assertEqual(len(list(root.glob("local.rules.*.bak"))), 2)

    def test_save_rules_rejects_path_outside_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "rules"
            root.mkdir()
            outside = Path(temp_dir) / "outside.rules"

            with self.assertRaises(ValueError):
                save_rules(str(outside), str(root), VALID_RULE)

            self.assertFalse(outside.exists())


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.rules_root = root / "rules"
        self.static_dir = root / "static"
        self.rules_root.mkdir()
        self.static_dir.mkdir()
        self.rules_path = self.rules_root / "local.rules"
        self.alert_path = root / "alert.log"
        self.rules_path.write_text(VALID_RULE, encoding="utf-8")
        self.alert_path.write_text("alert one\n", encoding="utf-8")
        (self.static_dir / "index.html").write_text("dashboard", encoding="utf-8")
        handler = make_handler(
            str(self.static_dir),
            str(self.rules_path),
            str(self.rules_root),
            str(self.alert_path),
            "test-token",
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp_dir.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection(self.host, self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read().decode("utf-8")
        connection.close()
        return response.status, json.loads(payload)

    def test_status_reports_rules_and_alerts(self):
        status, payload = self.request("GET", "/api/status")

        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(payload["rulesExists"])
        self.assertTrue(payload["alertExists"])
        self.assertTrue(payload["writeTokenRequired"])

    def test_post_rules_requires_write_token(self):
        status, payload = self.request("POST", "/api/rules", body=VALID_RULE)

        self.assertEqual(status, HTTPStatus.FORBIDDEN)
        self.assertEqual(payload["error"], "invalid dashboard write token")
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), VALID_RULE)

    def test_invalid_rule_does_not_overwrite_current_rules(self):
        status, payload = self.request(
            "POST",
            "/api/rules",
            body="alert tcp any any -> any 80 sid:1;",
            headers={"X-Dashboard-Token": "test-token"},
        )

        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(payload["error"], "rule validation failed")
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), VALID_RULE)

    def test_invalid_utf8_payload_is_rejected(self):
        status, payload = self.request(
            "POST",
            "/api/rules",
            body=b"\xff\xfe",
            headers={"X-Dashboard-Token": "test-token"},
        )

        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(payload["error"], "rule payload must be valid utf-8")
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), VALID_RULE)

    def test_valid_rule_save_updates_file(self):
        new_rule = 'drop tcp any any -> $HOME_NET 80 (msg:"Block admin URL"; content:"/admin"; http_uri; sid:1000006; rev:1;)'

        status, payload = self.request(
            "POST",
            "/api/rules",
            body=new_rule,
            headers={"X-Dashboard-Token": "test-token"},
        )

        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(payload["ok"])
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), f"{new_rule}\n")


if __name__ == "__main__":
    unittest.main()
