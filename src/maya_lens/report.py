from __future__ import annotations

import html
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .public_safety import PUBLIC_NO_SIGNAL, PUBLIC_REVIEW, PUBLIC_RISK, build_public_projection, public_state

_REPORT_WRITE_LOCK = threading.Lock()


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _axis_status_label(axis: dict[str, Any]) -> str:
    return public_state(axis.get("status_label") or {"green": PUBLIC_NO_SIGNAL, "blue": PUBLIC_REVIEW, "amber": PUBLIC_REVIEW, "orange": PUBLIC_REVIEW, "red": PUBLIC_RISK}.get(axis.get("color"), PUBLIC_REVIEW))


def _public_review_label(value: Any, fallback: str = "Sentinel review") -> str:
    return str(value or fallback)


def _recommended_actions(triage: dict[str, Any]) -> list[str]:
    return list(triage.get("recommended_actions") or [])


def render_markdown_report(result: dict[str, Any]) -> str:
    result = build_public_projection(result)
    lines: list[str] = []
    lines.append(f"# MAYA Sentinel — {result.get('source_zip', 'repo.zip')}")
    lines.append("")
    lines.append(f"> {result['disclaimer']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Fence:** `{result['fence']}`")
    lines.append(f"- **Status:** `{result['status']}`")
    lines.append(f"- **Repo identity:** {result.get('metadata', {}).get('repo_identity', 'Unknown')}")
    lines.append(f"- **Source SHA256:** `{result.get('source_sha256', '')}`")
    lines.append(f"- **Next step:** {result.get('summary', {}).get('next_step', '')}")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append("| Metric | Status | Interpretation |")
    lines.append("|---|---|---|")
    for name, axis in result.get("axes", {}).items():
        note = axis['interpretation']
        if axis.get("reward_note"):
            note += f" MAYA: {axis['reward_note']}"
        if axis.get("review_options"):
            note += " Suggested checks: " + "; ".join(axis.get("review_options", []))
        lines.append(f"| {name} | {_axis_status_label(axis)} | {note} |")
    lines.append("")
    lines.append("## What MAYA Checked")
    lines.append("")
    lines.append("- ZIP extraction safety guards")
    lines.append("- File inventory and storage footprint")
    lines.append("- Governance, approval-policy docs, and maintenance workflow signals")
    lines.append("- Dependency manifests and install hooks")
    lines.append("- Credential-shaped values, redacted")
    lines.append("- Process/network/filesystem/persistence patterns")
    lines.append("- Binary/blob surface")
    lines.append("- README/license/source provenance signals")
    lines.append("- AI/component BOM, artifact receipt, public receipt, action-boundary review, finding groups, remediation plan, and security routing")
    lines.append("")
    lines.append("## AI / Component BOM")
    lines.append("")
    ai_bom = result.get("ai_bom", {})
    lines.append(f"- **BOM version:** `{ai_bom.get('version', 'not available')}`")
    lines.append(f"- **AI/component count:** {ai_bom.get('component_count', 0)}")
    lines.append(f"- **Direct dependencies:** {ai_bom.get('dependency_direct_count', 0)}")
    lines.append(f"- **Component types:** `{json.dumps(ai_bom.get('component_type_counts', {}), ensure_ascii=False)}`")
    lines.append("")
    for component in ai_bom.get("components", [])[:20]:
        lines.append(f"- `{component.get('type')}` — `{component.get('path')}`")
    if len(ai_bom.get("components", [])) > 20:
        lines.append(f"- `... +{len(ai_bom.get('components', [])) - 20} more`")
    lines.append("")
    lines.append("## Artifact Receipt")
    lines.append("")
    receipt = result.get("artifact_receipt", {})
    governance = result.get("governance_surface", {})
    lines.append(f"- **Receipt version:** `{receipt.get('version', 'not available')}`")
    lines.append(f"- **Static only:** `{receipt.get('static_only', True)}`")
    lines.append(f"- **Archive safety:** `{receipt.get('archive_safety', {}).get('status', 'unknown')}`")
    if receipt.get('archive_safety', {}).get('blocked_reason'):
        lines.append(f"- **Blocked reason:** `{receipt.get('archive_safety', {}).get('blocked_reason')}`")
    lines.append(f"- **Executed repo code:** `{receipt.get('executed_repo_code', False)}`")
    lines.append(f"- **Installed dependencies:** `{receipt.get('installed_dependencies', False)}`")
    lines.append(f"- **Network calls:** `{receipt.get('network_calls', False)}`")
    lines.append(f"- **Manifest files:** `{receipt.get('manifest_file_count', 0)}` · **Lockfiles:** `{receipt.get('lockfile_count', 0)}` · **Install hooks:** `{receipt.get('install_hook_count', 0)}`")

    public_receipt = result.get("public_receipt", {})
    action_boundary = result.get("action_boundary_review", {})
    lines.append("## Public Receipt")
    lines.append("")
    lines.append(f"- **Receipt version:** `{public_receipt.get('version', 'not available')}`")
    lines.append(f"- **Static only:** `{public_receipt.get('static_only', True)}`")
    lines.append(f"- **Executed repo code:** `{public_receipt.get('executed_repo_code', False)}`")
    lines.append(f"- **Installed dependencies:** `{public_receipt.get('installed_dependencies', False)}`")
    lines.append(f"- **Human gate required:** `{public_receipt.get('human_gate_required', False)}`")
    if public_receipt.get("action_boundaries"):
        lines.append(f"- **Action boundaries:** {', '.join(public_receipt.get('action_boundaries', []))}")
    for action in public_receipt.get("recommended_actions", [])[:6]:
        lines.append(f"- **Recommended action:** {_public_review_label(action)}")
    lines.append("")

    lines.append("## Action Boundary Review")
    lines.append("")
    lines.append(f"- **Decision:** `{action_boundary.get('decision', 'standard_static_review')}`")
    lines.append(f"- **Manual approval required:** `{action_boundary.get('manual_approval_required', False)}`")
    integrity = action_boundary.get("instruction_surface_integrity", {})
    lines.append(f"- **Instruction surface:** `{integrity.get('status', 'not available')}`")
    lines.append(f"- **Instruction/MCP/workflow counts:** agent `{integrity.get('agent_instruction_count', 0)}` · MCP `{integrity.get('mcp_server_count', 0)}` · workflow `{integrity.get('workflow_automation_count', 0)}` · approval docs `{integrity.get('approval_doc_count', 0)}`")
    for item in action_boundary.get("authority_classes", [])[:12]:
        lines.append(f"- **{item.get('label', 'Authority class')}:** {item.get('evidence_count', 0)} signal(s) · {_public_review_label(item.get('recommended_action', 'Review before action.'))}")
    for check in integrity.get("checks", [])[:6]:
        lines.append(f"- **Integrity check:** {_public_review_label(check)}")
    lines.append("")

    lines.append("## Governance / Approval Surface")
    lines.append("")
    governance_counts = governance.get("counts", {})
    lines.append(f"- **Surface version:** `{governance.get('version', 'not available')}`")
    lines.append(f"- **Approval docs:** `{governance_counts.get('approval_docs', 0)}` · **Security policies:** `{governance_counts.get('security_policy_files', 0)}` · **Contributing guides:** `{governance_counts.get('contributing_guides', 0)}`")
    lines.append(f"- **Changelogs:** `{governance_counts.get('changelog_files', 0)}` · **Release workflows:** `{governance_counts.get('release_workflows', 0)}` · **Docs workflows:** `{governance_counts.get('docs_workflows', 0)}`")
    lines.append(f"- **Issue templates:** `{governance_counts.get('issue_templates', 0)}` · **CODEOWNERS files:** `{governance_counts.get('codeowners_files', 0)}`")
    for item in governance.get("approval_docs", [])[:12]:
        lines.append(f"- **Approval doc:** `{item.get('path', '')}` · {item.get('signal', '')}")
    for item in governance.get("workflow_signals", [])[:12]:
        lines.append(f"- **Workflow:** `{item.get('path', '')}` · {item.get('signal', '')}")
    for item in governance.get("maintenance_signals", [])[:12]:
        lines.append(f"- **Maintenance signal:** `{item.get('path', '')}` · {item.get('signal', '')}")

    security_tool_surface = result.get("security_tool_surface", {})
    security_counts = security_tool_surface.get("counts", {})
    lines.append("## Security Tool Surface")
    lines.append("")
    lines.append(f"- **Posture:** `{security_tool_surface.get('posture', 'not available')}`")
    lines.append(f"- **Human scope required:** `{security_tool_surface.get('human_scope_required', False)}`")
    lines.append(f"- **Counts:** `{json.dumps(security_counts, ensure_ascii=False)}`")
    for item in security_tool_surface.get("signals", [])[:16]:
        lines.append(f"- **{item.get('label', item.get('id', 'surface'))}:** `{item.get('path', '')}` · {_public_review_label(item.get('recommended_action', 'Review before promotion.'))}")
    for action in security_tool_surface.get("recommended_review_actions", [])[:5]:
        lines.append(f"- **Review action:** {_public_review_label(action)}")
    lines.append("")

    lines.append("## Finding Groups")
    lines.append("")
    groups = result.get("finding_groups", [])
    if groups:
        lines.append("| Count | Max Severity | Category | Signal | Sample paths |")
        lines.append("|---:|---|---|---|---|")
        for group in groups[:40]:
            lines.append(f"| {group.get('count', 0)} | {group.get('max_severity', '')} | {group.get('category', '')} | {group.get('signal', '')} | `{', '.join(group.get('sample_paths', [])[:3])}` |")
    else:
        lines.append("No finding groups were produced.")
    lines.append("")
    lines.append("## Remediation Plan")
    lines.append("")
    plan = result.get("remediation_plan", [])
    if plan:
        for item in plan:
            lines.append(f"{item.get('priority', 0)}. **{item.get('category', 'review')}** — {item.get('action', '')}")
    else:
        lines.append("No deterministic remediation steps were generated from static findings.")
    lines.append("")
    lines.append("## Advisory Triage")
    lines.append("")
    triage = result.get("advisory_triage", {})
    lines.append(f"- **Urgency:** `{triage.get('urgency', 'review')}`")
    lines.append(f"- **Review route:** `{_public_review_label(triage.get('owner', 'Sentinel review'))}`")
    lines.append(f"- **Primary focus:** `{', '.join(triage.get('primary_focus', []))}`")
    for item in triage.get("top_categories", [])[:5]:
        lines.append(f"- **{item.get('category', 'signal')}** · {item.get('signal', '')} · count `{item.get('count', 0)}` · max `{item.get('max_severity', 'info')}`")
    for action in _recommended_actions(triage):
        lines.append(f"- {_public_review_label(action)}")
    lines.append("")
    lines.append("## Agentic / MCP Surface")
    lines.append("")
    agentic = result.get("agentic_surface", {})
    lines.append(f"- **Posture:** `{agentic.get('posture', 'reference_only')}`")
    lines.append(f"- **Review route:** `{_public_review_label(agentic.get('owner', 'Sentinel review'))}`")
    counts = agentic.get("component_counts", {})
    lines.append(f"- **Counts:** `{json.dumps(counts, ensure_ascii=False)}`")
    for surface in agentic.get("surfaces", []):
        lines.append(f"- **{surface.get('label', surface.get('surface', 'surface'))}:** `{surface.get('count', 0)}`")
    for check in agentic.get("policy_checks", [])[:8]:
        lines.append(f"- **{check.get('surface', 'surface')} check:** {check.get('check', '')}")
    lines.append("")
    lines.append("## Security Routing")
    lines.append("")
    routing = result.get("security_routing", {})
    lines.append(f"- **Decision:** `{routing.get('decision', 'not available')}`")
    lines.append(f"- **Tier 1 screen:** `{routing.get('tier1_screen', 'not available')}`")
    lines.append(f"- **Human gate required:** `{routing.get('human_gate_required', False)}`")
    lines.append(f"- **Recommended review path:** {_public_review_label(routing.get('recommended_lane', 'No routing recommendation available.'))}")
    for reason in routing.get("why", []):
        lines.append(f"- {_public_review_label(reason)}")
    lines.append("")
    lines.append("## What MAYA Did Not Check")
    lines.append("")
    for item in result.get("summary", {}).get("not_checked", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = result.get("findings", [])
    if not findings:
        lines.append("No static findings were detected by v0.2. This does not prove the repo is safe.")
    else:
        lines.append("| Severity | Category | Path | Line | Signal | Evidence |")
        lines.append("|---|---|---|---:|---|---|")
        for finding in findings[:250]:
            lines.append(
                f"| {finding['severity']} | {finding['category']} | `{finding['path']}` | "
                f"{finding.get('line') or ''} | {finding['signal']} | `{finding.get('snippet', '')}` |"
            )
    lines.append("")
    lines.append("## Inventory")
    lines.append("")
    inv = result.get("inventory", {})
    lines.append(f"- **Files:** {inv.get('file_count', 0)}")
    lines.append(f"- **Directories:** {inv.get('dir_count', 0)}")
    lines.append(f"- **Extracted MB:** {inv.get('total_mb', 0)}")
    lines.append(f"- **Top extensions:** `{json.dumps(inv.get('extensions', {}), ensure_ascii=False)}`")
    lines.append("")
    return "\n".join(lines)


def render_html_report(result: dict[str, Any]) -> str:
    result = build_public_projection(result)
    axes = result.get("axes", {})
    findings = result.get("findings", [])
    ai_bom = result.get("ai_bom", {})
    receipt = result.get("artifact_receipt", {})
    finding_groups = result.get("finding_groups", [])
    remediation_plan = result.get("remediation_plan", [])
    def render_inline_signals(items: list[Any]) -> str:
        entries = [item for item in items if item not in (None, "")]
        if not entries:
            return ""
        return '<p class="inline-signal-row">' + "".join(f'<span class="inline-signal">{_escape(item)}</span>' for item in entries) + "</p>"

    def render_axis_card(name: str, axis: dict[str, Any]) -> str:
        reward = f'<p class="maya-note"><strong>MAYA</strong> {_escape(axis.get("reward_note"))}</p>' if axis.get("reward_note") else ""
        options = f'<div class="suggested-checks"><strong>Suggested checks</strong>{render_inline_signals(axis.get("review_options", []))}</div>' if axis.get("review_options") else ""
        return f"""
        <section class=\"metric-card {axis['color']}\">
          <div class=\"metric-top\"><h3>{_escape(name)}</h3></div>
          <div class=\"bar\"><i></i><span>{_escape(_axis_status_label(axis))}</span></div>
          <p>{_escape(axis['interpretation'])}</p>
          {reward}
          {options}
        </section>
        """

    axis_cards = "\n".join(render_axis_card(name, axis) for name, axis in axes.items())
    if findings:
        finding_rows = "\n".join(
            f"<tr><td>{_escape(f['severity'])}</td><td>{_escape(f['category'])}</td><td><code>{_escape(f['path'])}</code></td><td>{_escape(f.get('line') or '')}</td><td>{_escape(f['signal'])}</td><td><code>{_escape(f.get('snippet', ''))}</code></td></tr>"
            for f in findings[:250]
        )
    else:
        finding_rows = "<tr><td colspan='6'>No static findings were detected by v0.2. This does not prove the repo is safe.</td></tr>"
    bom_rows = "\n".join(
        f"<tr><td>{_escape(c.get('type', ''))}</td><td><code>{_escape(c.get('path', ''))}</code></td><td>{_escape(c.get('reason', ''))}</td></tr>"
        for c in ai_bom.get("components", [])[:80]
    ) or "<tr><td colspan='3'>No AI/component BOM entries detected.</td></tr>"
    group_rows = "\n".join(
        f"<tr><td>{_escape(g.get('count', 0))}</td><td>{_escape(g.get('max_severity', ''))}</td><td>{_escape(g.get('category', ''))}</td><td>{_escape(g.get('signal', ''))}</td><td><code>{_escape(', '.join(g.get('sample_paths', [])[:3]))}</code></td></tr>"
        for g in finding_groups[:60]
    ) or "<tr><td colspan='5'>No finding groups produced.</td></tr>"
    remediation_items = "\n".join(
        f"<li><strong>{_escape(item.get('category', 'review'))}</strong> — {_escape(item.get('action', ''))}</li>"
        for item in remediation_plan[:20]
    ) or "<li>No deterministic remediation steps were generated from static findings.</li>"
    governance = result.get("governance_surface", {})
    governance_counts = governance.get("counts", {})
    approval_rows = "\n".join(
        f"<tr><td><code>{_escape(item.get('path', ''))}</code></td><td>{_escape(item.get('signal', ''))}</td></tr>"
        for item in governance.get("approval_docs", [])[:20]
    ) or "<tr><td colspan='2'>No approval/policy docs detected.</td></tr>"
    workflow_rows = "\n".join(
        f"<tr><td><code>{_escape(item.get('path', ''))}</code></td><td>{_escape(item.get('signal', ''))}</td></tr>"
        for item in governance.get("workflow_signals", [])[:20]
    ) or "<tr><td colspan='2'>No release/docs workflows detected.</td></tr>"
    maintenance_items = "\n".join(
        f"<li><code>{_escape(item.get('path', ''))}</code> — {_escape(item.get('signal', ''))}</li>"
        for item in governance.get("maintenance_signals", [])[:20]
    ) or "<li>No maintenance signals detected.</li>"
    security_tool_surface = result.get("security_tool_surface", {})
    security_counts = security_tool_surface.get("counts", {})
    security_rows = "\n".join(
        f"<tr><td>{_escape(item.get('label', item.get('id', 'surface')))}</td><td><code>{_escape(item.get('path', ''))}</code></td><td>{_escape(_public_review_label(item.get('recommended_action', 'Review before promotion.')))}</td></tr>"
        for item in security_tool_surface.get("signals", [])[:24]
    ) or "<tr><td colspan='3'>No scanner/API/MCP security-tool surface detected.</td></tr>"
    security_actions = "\n".join(
        f"<li>{_escape(_public_review_label(action))}</li>" for action in security_tool_surface.get("recommended_review_actions", [])[:6]
    ) or "<li>No security-tool follow-up actions emitted.</li>"
    advisory_triage = result.get("advisory_triage", {})
    triage_rows = "\n".join(
        f"<tr><td>{_escape(item.get('category', 'signal'))}</td><td>{_escape(item.get('signal', ''))}</td><td>{_escape(item.get('count', 0))}</td><td>{_escape(item.get('max_severity', 'info'))}</td></tr>"
        for item in advisory_triage.get("top_categories", [])[:5]
    ) or "<tr><td colspan='4'>No grouped advisory categories were produced.</td></tr>"
    triage_actions = "\n".join(
        f"<li>{_escape(_public_review_label(action))}</li>" for action in _recommended_actions(advisory_triage)
    ) or "<li>No recommended follow-up actions were generated.</li>"
    agentic_surface = result.get("agentic_surface", {})
    agentic_rows = "\n".join(
        f"<tr><td>{_escape(surface.get('label', surface.get('surface', 'surface')))}</td><td>{_escape(surface.get('count', 0))}</td><td>{_escape(surface.get('surface', 'surface'))}</td></tr>"
        for surface in agentic_surface.get("surfaces", [])
    ) or "<tr><td colspan='3'>No agentic surfaces detected.</td></tr>"
    agentic_checks = "\n".join(
        f"<li><strong>{_escape(item.get('surface', 'surface'))}</strong> — {_escape(item.get('check', ''))}</li>"
        for item in agentic_surface.get("policy_checks", [])[:8]
    ) or "<li>No extra agentic checks were generated.</li>"
    routing = result.get("security_routing", {})
    routing_decision = _escape(routing.get("decision", "not available"))
    routing_human_gate = _escape(str(routing.get("human_gate_required", False)))
    routing_lane = _escape(_public_review_label(routing.get("recommended_lane", "")))
    routing_why = "\n".join(
        f"<li>{_escape(_public_review_label(reason))}</li>" for reason in routing.get("why", [])
    ) or "<li>No routing reasons available.</li>"
    receipt_json = _escape(json.dumps(receipt, indent=2))
    public_receipt = result.get("public_receipt", {})
    public_receipt_json = _escape(json.dumps(public_receipt, indent=2))
    action_boundary = result.get("action_boundary_review", {})
    action_rows = "\n".join(
        f"<tr><td>{_escape(item.get('label', 'Authority class'))}</td><td>{_escape(item.get('evidence_count', 0))}</td><td>{_escape(_public_review_label(item.get('recommended_action', 'Review before action.')))}</td></tr>"
        for item in action_boundary.get("authority_classes", [])[:12]
    ) or "<tr><td colspan='3'>No authority-sensitive action classes detected.</td></tr>"
    integrity = action_boundary.get("instruction_surface_integrity", {})
    integrity_checks = "\n".join(
        f"<li>{_escape(_public_review_label(check))}</li>" for check in integrity.get("checks", [])[:8]
    ) or "<li>No extra instruction-surface checks emitted.</li>"
    public_actions = "\n".join(
        f"<li>{_escape(_public_review_label(action))}</li>" for action in public_receipt.get("recommended_actions", [])[:8]
    ) or "<li>No public follow-up actions emitted.</li>"
    return f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
<title>MAYA Sentinel — {_escape(result.get('source_zip', 'repo.zip'))}</title>
<style>
:root{{--bg:#12100f;--panel:#1a1816;--panel2:#201d1a;--text:#f2e6df;--muted:#a3968e;--accent:#ff7a39;--border:#3d2a1a;--green:#58c88a;--blue:#6fa7d7;--amber:#f2c777;--orange:#ff7a39;--red:#d95f56;}}
body{{margin:0;background:radial-gradient(circle at 20% 0%,rgba(255,122,57,.12),transparent 30%),var(--bg);color:var(--text);font-family:Segoe UI,system-ui,sans-serif;padding:36px;}}
main{{max-width:1180px;margin:0 auto;}}
header{{border:1px solid var(--border);background:rgba(26,24,22,.92);border-radius:18px;padding:28px;margin-bottom:22px;}}
h1{{margin:0;font-size:30px;letter-spacing:-.04em;}} .sub{{color:var(--muted);margin-top:8px;}} .disclaimer{{color:var(--amber);margin-top:14px;font-weight:600;}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;}}
.metric-card{{border:1px solid var(--border);background:var(--panel);border-radius:16px;padding:18px;}}
.metric-top{{display:flex;justify-content:space-between;gap:12px;align-items:center;}} .metric-top h3{{margin:0;font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);}}
.bar{{position:relative;height:22px;background:#2a2420;border-radius:99px;overflow:hidden;margin:13px 0 10px;border:1px solid rgba(242,199,119,.12);}} .bar i{{display:block;height:100%;width:100%;border-radius:99px;}} .bar span{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:10px;line-height:1;letter-spacing:.16em;text-transform:uppercase;font-weight:950;color:#120f0d;text-shadow:0 1px 0 rgba(255,255,255,.22);}}
.green .bar{{box-shadow:0 0 14px rgba(88,200,138,.11);}} .green .bar i{{background:linear-gradient(90deg,#3f9563 0%,#62ba83 54%,#78cca0 100%);filter:saturate(.82) brightness(.92);}} .blue .bar{{box-shadow:0 0 13px rgba(111,167,215,.10);}} .blue .bar i,.amber .bar i,.orange .bar i{{background:linear-gradient(90deg,#25445f 0%,#5b90bc 54%,#85afd0 100%);filter:saturate(.78) brightness(.92);}} .red .bar i{{background:linear-gradient(90deg,#6f2726 0%,#c64f4a 58%,#df776b 100%);filter:saturate(.82) brightness(.93);}} .blue .bar span,.amber .bar span,.orange .bar span,.red .bar span{{color:#fff3ea;text-shadow:0 1px 4px rgba(0,0,0,.55);}}
.maya-note{{color:#d8eadf;background:rgba(70,130,88,.045);border:1px solid rgba(88,200,138,.13);border-radius:11px;padding:9px 10px;}} .maya-note strong{{display:block;margin:0 0 4px;color:#e5f3e8;font-size:10px;letter-spacing:.16em;text-transform:uppercase;}} .suggested-checks{{margin-top:12px;color:rgba(243,235,229,.62);font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.08em;}} .suggested-checks>strong{{display:block;color:rgba(243,235,229,.58);margin-bottom:7px;}} .inline-signal-row{{display:flex;flex-wrap:wrap;gap:7px 0;margin:0;color:rgba(243,235,229,.74);font-size:11px;line-height:1.45;text-transform:none;letter-spacing:normal;}} .inline-signal{{display:inline-flex;align-items:baseline;white-space:nowrap;color:#cad5df;font-weight:850;letter-spacing:.025em;margin-right:14px;}} .inline-signal:not(:last-child)::after{{content:"";width:3px;height:3px;border-radius:50%;background:rgba(255,122,57,.52);margin-left:12px;align-self:center;box-shadow:0 0 8px rgba(255,122,57,.24);}}
.card{{border:1px solid var(--border);background:var(--panel);border-radius:16px;padding:20px;margin-top:18px;}} table{{width:100%;border-collapse:collapse;font-size:13px;}} th,td{{border-bottom:1px solid var(--border);padding:10px;text-align:left;vertical-align:top;}} th{{color:var(--accent);text-transform:uppercase;font-size:11px;letter-spacing:.08em;}} code{{color:var(--amber);white-space:pre-wrap;word-break:break-word;}}
</style>
</head>
<body><main>
<header>
  <h1>MAYA Sentinel</h1>
  <div class=\"sub\">{_escape(result.get('source_zip', 'repo.zip'))} · status {_escape(result.get('status', 'unknown'))} · fence {_escape(result.get('fence', ''))}</div>
  <div class=\"disclaimer\">{_escape(result.get('disclaimer', ''))}</div>
</header>
<section class=\"metrics\">{axis_cards}</section>
<section class=\"card\"><h2>AI / Component BOM</h2><p>{_escape(ai_bom.get('component_count', 0))} component signal(s), {_escape(ai_bom.get('dependency_direct_count', 0))} direct dependency signal(s).</p><table><thead><tr><th>Type</th><th>Path</th><th>Reason</th></tr></thead><tbody>{bom_rows}</tbody></table></section>
<section class=\"card\"><h2>Artifact Receipt</h2><pre><code>{receipt_json}</code></pre></section>
<section class=\"card\"><h2>Public Receipt</h2><p>Static only: <code>{_escape(public_receipt.get('static_only', True))}</code> · Executed repo code: <code>{_escape(public_receipt.get('executed_repo_code', False))}</code> · Human gate: <code>{_escape(public_receipt.get('human_gate_required', False))}</code></p><ol>{public_actions}</ol><pre><code>{public_receipt_json}</code></pre></section>
<section class=\"card\"><h2>Action Boundary Review</h2><p>Decision: <code>{_escape(action_boundary.get('decision', 'standard_static_review'))}</code> · Manual approval required: <code>{_escape(action_boundary.get('manual_approval_required', False))}</code> · Instruction surface: <code>{_escape(integrity.get('status', 'not available'))}</code></p><p>Agent instructions: <code>{_escape(integrity.get('agent_instruction_count', 0))}</code> · MCP servers: <code>{_escape(integrity.get('mcp_server_count', 0))}</code> · Workflows: <code>{_escape(integrity.get('workflow_automation_count', 0))}</code> · Approval docs: <code>{_escape(integrity.get('approval_doc_count', 0))}</code></p><table><thead><tr><th>Authority class</th><th>Signals</th><th>Recommended action</th></tr></thead><tbody>{action_rows}</tbody></table><ul>{integrity_checks}</ul></section>
<section class=\"card\"><h2>Governance / Approval Surface</h2><p>Approval docs: <code>{_escape(governance_counts.get("approval_docs", 0))}</code> · Security policies: <code>{_escape(governance_counts.get("security_policy_files", 0))}</code> · Contributing guides: <code>{_escape(governance_counts.get("contributing_guides", 0))}</code></p><p>Changelogs: <code>{_escape(governance_counts.get("changelog_files", 0))}</code> · Release workflows: <code>{_escape(governance_counts.get("release_workflows", 0))}</code> · Docs workflows: <code>{_escape(governance_counts.get("docs_workflows", 0))}</code></p><p>Issue templates: <code>{_escape(governance_counts.get("issue_templates", 0))}</code> · CODEOWNERS: <code>{_escape(governance_counts.get("codeowners_files", 0))}</code></p><h3>Approval docs</h3><table><thead><tr><th>Path</th><th>Signal</th></tr></thead><tbody>{approval_rows}</tbody></table><h3>Release / docs workflows</h3><table><thead><tr><th>Path</th><th>Signal</th></tr></thead><tbody>{workflow_rows}</tbody></table><h3>Maintenance signals</h3><ul>{maintenance_items}</ul></section>
<section class=\"card\"><h2>Security Tool Surface</h2><p>Posture: <code>{_escape(security_tool_surface.get('posture', 'not available'))}</code> · Human scope required: <code>{_escape(security_tool_surface.get('human_scope_required', False))}</code></p><blockquote><code>{_escape(json.dumps(security_counts, ensure_ascii=False))}</code></blockquote><table><thead><tr><th>Surface</th><th>Path</th><th>Recommended action</th></tr></thead><tbody>{security_rows}</tbody></table><ul>{security_actions}</ul></section>
<section class=\"card\"><h2>Finding Groups</h2><table><thead><tr><th>Count</th><th>Max Severity</th><th>Category</th><th>Signal</th><th>Samples</th></tr></thead><tbody>{group_rows}</tbody></table></section>
<section class=\"card\"><h2>Remediation Plan</h2><ol>{remediation_items}</ol></section>
<section class=\"card\"><h2>Advisory Triage</h2><p>Urgency: <code>{_escape(advisory_triage.get('urgency', 'review'))}</code> · Review route: <code>{_escape(_public_review_label(advisory_triage.get('owner', 'Sentinel review')))}</code></p><blockquote>{_escape(', '.join(advisory_triage.get('primary_focus', [])))}</blockquote><table><thead><tr><th>Category</th><th>Signal</th><th>Count</th><th>Max Severity</th></tr></thead><tbody>{triage_rows}</tbody></table><ul>{triage_actions}</ul></section>
<section class=\"card\"><h2>Agent/tooling surface</h2><p>Posture: <code>{_escape(agentic_surface.get('posture', 'reference_only'))}</code> · Review route: <code>{_escape(_public_review_label(agentic_surface.get('owner', 'Sentinel review')))}</code></p><blockquote><code>{_escape(json.dumps(agentic_surface.get('component_counts', {}), ensure_ascii=False))}</code></blockquote><table><thead><tr><th>Surface</th><th>Count</th><th>Key</th></tr></thead><tbody>{agentic_rows}</tbody></table><ul>{agentic_checks}</ul></section>
<section class=\"card\"><h2>Security Routing</h2><p>Decision: <code>{routing_decision}</code> · Human gate: <code>{routing_human_gate}</code></p><blockquote>{routing_lane}</blockquote><ul>{routing_why}</ul></section>
<section class=\"card\"><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Path</th><th>Line</th><th>Signal</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table></section>
<section class=\"card\"><h2>Inventory</h2><pre><code>{_escape(json.dumps(result.get('inventory', {}), indent=2))}</code></pre></section>
</main></body></html>"""


def _safe_stem(value: Any) -> str:
    stem = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in Path(str(value or "repo")).stem)[:70]
    return stem.strip("._ ") or "repo"


def _scan_id(result: dict[str, Any], safe_stem: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    sha = ''.join(ch for ch in str(result.get("source_sha256", "")) if ch.lower() in "0123456789abcdef")[:12] or "nohash"
    return f"{stamp}_{sha}_{uuid.uuid4().hex[:8]}_{safe_stem}"


def _atomic_write_new(path: Path, text: str) -> None:
    temp_name = f".{path.name}.{uuid.uuid4().hex}.tmp"
    temp_path = path.with_name(temp_name)
    try:
        with temp_path.open("x", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if path.exists():
            raise FileExistsError(path)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def write_reports(result: dict[str, Any], reports_dir: str | Path) -> dict[str, str]:
    reports = Path(reports_dir)
    reports.mkdir(parents=True, exist_ok=True)
    public_result = build_public_projection(result)
    safe_stem = _safe_stem(public_result.get('source_zip', 'repo'))
    # This lock protects report/history consistency inside this Python process.
    # It is not a cross-process retention or coordination control.
    with _REPORT_WRITE_LOCK:
        while True:
            scan_id = _scan_id(public_result, safe_stem)
            names = {
                "markdown": f"{scan_id}.md",
                "html": f"{scan_id}.html",
                "json": f"{scan_id}.json",
            }
            if not any((reports / name).exists() for name in names.values()):
                break
        public_result["reports"] = names
        _atomic_write_new(reports / names["markdown"], render_markdown_report(public_result))
        _atomic_write_new(reports / names["html"], render_html_report(public_result))
        _atomic_write_new(reports / names["json"], json.dumps(public_result, ensure_ascii=False, indent=2))
    return names
