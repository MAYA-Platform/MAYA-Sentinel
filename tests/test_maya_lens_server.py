import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import maya_lens_server


class MayaLensServerTests(unittest.TestCase):
    def test_all_responses_emit_public_browser_hardening_headers(self):
        handler = maya_lens_server.MayaLensHandler.__new__(maya_lens_server.MayaLensHandler)
        headers = {}
        handler.wfile = io.BytesIO()
        handler.send_response = lambda _status: None
        handler.send_header = lambda name, value: headers.__setitem__(name, value)
        handler.end_headers = lambda: None

        handler._send(200, b"{}", "application/json; charset=utf-8")

        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("camera=()", headers["Permissions-Policy"])
        self.assertIn("microphone=()", headers["Permissions-Policy"])
        self.assertIn("serial=()", headers["Permissions-Policy"])
        self.assertIn("bluetooth=()", headers["Permissions-Policy"])

    def test_no_browser_does_not_open_ui_when_existing_server_is_alive(self):
        def fail_open_ui():
            raise AssertionError("open_ui should not be called when --no-browser is set")

        with patch.object(sys, "argv", ["maya_lens_server.py", "--no-browser"]), \
             patch.object(maya_lens_server, "server_alive", return_value=True), \
             patch.object(maya_lens_server, "open_ui", side_effect=fail_open_ui):
            self.assertEqual(maya_lens_server.main(), 0)


if __name__ == "__main__":
    unittest.main()
