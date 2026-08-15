from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import maya_lens_server


class PublicReleaseContractTests(unittest.TestCase):
    def test_public_metadata_and_runtime_files_exist(self):
        required = [
            "README.md", "LICENSE.txt", "SECURITY.md", "SAFETY_BOUNDARY.md",
            "maya_lens_server.py", "web/index.html", "web/styles.css", "web/app.js",
            "src/maya_lens/scanner.py", "src/maya_lens/public_safety.py",
        ]
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_readme_commands_are_standalone_and_reference_shipped_files(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("tools/maya-lens", readme)
        self.assertNotIn("sentinel_p1_reproduction", readme)
        self.assertIn("python tests/test_maya_lens_scanner.py", readme)
        self.assertIn("python tests/test_maya_lens_server.py", readme)

    def test_server_declares_complete_browser_hardening_set(self):
        source = (ROOT / "maya_lens_server.py").read_text(encoding="utf-8")
        for header in (
            "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ):
            self.assertIn(header, source)

    def test_mobile_history_keeps_touch_target_and_full_scan_id_semantics(self):
        styles = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        mobile_css = styles.split("@media (max-width: 760px)", 1)[1].split("@media", 1)[0]
        self.assertRegex(mobile_css, r"#clearHistoryButton\s*\{[^}]*min-height:\s*44px")
        self.assertIn("function formatScanIdForDisplay", app)
        self.assertIn("formatScanIdForDisplay(item.scan_id", app)
        self.assertIn('title="${escapeHtml(item.scan_id || \'retained scan\')}"', app)
        self.assertIn('data-scan-id="${escapeHtml(item.scan_id || \'\')}"', app)

    def test_release_manifest_has_no_private_source_paths(self):
        manifest = json.loads((ROOT / "PUBLIC_RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        for entry in manifest.get("files", []):
            relative = Path(entry.get("path", ""))
            self.assertFalse(relative.is_absolute())
            self.assertNotIn("..", relative.parts)

    def test_public_tree_excludes_non_public_vocabulary(self):
        # Blocked SHA-256 digests of tokens/phrases that must NOT appear in the
        # public repo (internal staff names, private identifiers, private role
        # names). The hash list is updated deliberately when public vocabulary
        # legitimately changes — e.g. "hermes" was removed on 2026-08-15 when
        # the phishing-detection surface added brand-impersonation coverage for
        # the public Hermes Agent project (hermes-agent.nousresearch.com), so
        # the protected brand name is now intentional public vocabulary.
        blocked = {
            "9ce00b27299cbd844c8a86508251fcdde9d040b9b1681ffd088580d489510628",
            "02adfd2e6940ca9602c65f4803f88c5c2b3540704ec56f37935ad933dbda1deb",
            "565a7aacd87653c32e0e2ba361d76cb5589ad9aa639e22349bb370479238eef1",
            "59458508a0827cff5f80ed091ebd8808fbe67c97357b58ca00a278e7359dec20",
            "386a85d8c88778b00b1355608363c7e3078857f3e9633cfd0802d3bf1c0b5b83",
            "6fef84656cd36b8a6daf342e5d73d71a146de9457e80f12f0bc611a40b688666",
            "ca83ebffa52a314b0f8d0b997a7716c968f5527d27bba95b6a76609aa04f3c0b",
            "a8cc7381b5deac8e2591ef0ac6ab2f6e748392f6da5b1cbba0596eda65e98b1e",
            "2d687e55e9ea7a94381713674cfb585b14495dc17d98c4c3c24b0e4fed77578e",
            "92146185ba55f681a0118969b252ce3a2449f8b20f3463b397b3da136bc6d6a7",
        }
        allowed_extensions = {".css", ".html", ".js", ".json", ".md", ".py", ".txt"}
        violations = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in allowed_extensions:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            tokens = re.findall(r"[a-z0-9_.-]+", text)
            words = re.findall(r"[a-z0-9]+", text)
            candidates = set(tokens)
            for width in range(2, 5):
                candidates.update(" ".join(words[index:index + width]) for index in range(len(words) - width + 1))
            for candidate in candidates:
                digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                if digest in blocked:
                    violations.append(f"{path.relative_to(ROOT)}:{digest[:12]}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
