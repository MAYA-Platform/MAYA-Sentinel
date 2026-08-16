"""Agentic-attack detection for MAYA Sentinel (ai-surface mode).

Static-only signal surface for prompt-injection, agent goal-hijack, MCP
tool-definition mutation, and indirect (XPIA / context-poisoning) attack
patterns carried inside a scanned repo.

Grounded in the following absorbed sources (2026-08-15 Bank batch):
  - j-dahl7/mcp-attack-detection-sentinel  (OWASP Top 10 for Agentic
    Applications 2026, ASI01-ASI07 hunting queries + analytics rules)
  - krishddd/security-module  (industrial prompt-injection / XPIA / poisoning
    payload libraries)
  - webpro255/awesome-ai-agent-attacks  (real incident timeline 2024-2026)

All checks are pure static pattern matching on file text. No network calls,
no model inference, no runtime sandboxing. A hit means "this repo carries
text that looks like an agentic attack payload or a goal-hijack instruction" —
advisory evidence, not attribution.

False-positive control mirrors scanner.classify_phishing_signals: the same
string in a documentation / README / test / fixture path is advisory (low),
whereas the same string in executable code, a data carrier, or a hidden
instruction surface is high. Security guides legitimately quote attack
phrases; an agent that imports a file full of live override payloads does not.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ASI01 — Agent Goal Hijack / direct prompt injection.
# Override, role reassignment, instruction extraction, system-prompt theft.
# ---------------------------------------------------------------------------
ASI01_GOAL_HIJACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("goal-hijack override instruction", re.compile(
        r"ignore (all |the )?(previous|prior|above|earlier) (instructions?|rules?|prompts?|context)", re.IGNORECASE)),
    ("goal-hijack disregard directive", re.compile(
        r"disregard (all |the )?(previous|prior|above|earlier) (instructions?|rules?|prompts?)", re.IGNORECASE)),
    ("goal-hijack forget directive", re.compile(
        r"(forget|discard) (everything|all (previous|prior|above|earlier))", re.IGNORECASE)),
    ("goal-hijack role override", re.compile(
        r"(you are now|your new role is|you are now a|act as (an |a )?|pretend (to be|you are)|override (your )?instructions?|do not (mention|follow|obey) )", re.IGNORECASE)),
    ("goal-hijack system-prompt extraction", re.compile(
        r"(system prompt|your instructions?|your (hidden |base )?prompt|reveal your (prompt|instructions|system)|output (your |the )?(system )?prompt verbatim|show me your (prompt|instructions|system prompt))", re.IGNORECASE)),
    ("goal-hijack fake system update", re.compile(
        r"(important system (update|message|note)|system override|\[system\s*override\]|as an (ai )?system)", re.IGNORECASE)),
    ("goal-hijack jailbreak unlock", re.compile(
        r"(jailbreak|developer mode|dan mode|do anything now|no restrictions|without (any )?restrictions|unfiltered|without (safety|content) (filters?|checks?|guardrails?))", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI02 — Tool Misuse & Exploitation.
# Unrestricted tool/executor coercion, safety-bypass instructions.
# ---------------------------------------------------------------------------
ASI02_TOOL_MISUSE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("tool-misuse bypass safety", re.compile(
        r"(bypass (the |any )?(safety|security|validation|sanitization|checks?|guardrails?|filters?)|without (any |the )?(safety|security|validation|sanitization|checks?|guardrails?|filters?))", re.IGNORECASE)),
    ("tool-misuse unrestricted executor", re.compile(
        r"(unrestricted (sql )?executor|execute (any|all) (query|command|code)|run (any|every) (query|command|code)|ignore the (safety|security|validation) )", re.IGNORECASE)),
    ("tool-misuse full-access grant", re.compile(
        r"(full access|elevated privileges?|administrator (access|role)|database administrator|root access|admin (role|access)|grant (me|the user|this agent) )", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI03 — Identity / Privilege Abuse (role elevation claims via payload).
# ---------------------------------------------------------------------------
ASI03_PRIVILEGE_ABUSE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("identity-abuse privilege elevation", re.compile(
        r"(elevat(e|ed) (privileges?|access)|escalat(e|ed) (privileges?|permissions?)|claim (admin|root|owner|administrator)|you have (elevated|admin|root|full) )", re.IGNORECASE)),
    ("identity-abuse high-priv role", re.compile(
        r"(owner|contributor|user access administrator|key vault administrator|storage blob data owner|role assignment)", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI04 — Supply Chain / MCP tool-definition mutation (rug pull).
# Register/rewrite an MCP server or tool definition from untrusted content.
# ---------------------------------------------------------------------------
ASI04_SUPPLY_CHAIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("supply-chain mcp config rewrite", re.compile(
        r"(rewrite (the )?mcp|modify mcp|mcp\.json|claude_desktop_config|register (an? |the )?(mcp|tool) (server|definition)|tool[- ]definition (mutation|change|injection))", re.IGNORECASE)),
    ("supply-chain mcp server rug pull", re.compile(
        r"(attacker[- ]controlled (mcp|tool|server)|malicious mcp server|toolserver|model-context-protocol)", re.IGNORECASE)),
    ("supply-chain hidden instruction carrier", re.compile(
        r"(white text on white|one[- ]pixel (text|font)|font[- ]size[:\s]*0|hidden (instruction|text|prompt)|invisible (text|instruction|prompt))", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI05 — Unexpected Code Execution / Exfiltration via injection payload.
# ---------------------------------------------------------------------------
ASI05_CODE_EXEC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("code-exec exfil encode", re.compile(
        r"(base64 (encode|decode)|exfiltrate|send to http|curl \||wget \||pipe (to|into) (bash|sh|zsh|powershell|cmd))", re.IGNORECASE)),
    ("code-exec pipe to shell", re.compile(
        r"(\| (bash|sh|zsh|powershell|cmd|/bin/sh))", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI06 — Memory & Context Poisoning / XPIA (indirect injection in data).
# The override string is embedded in a data-source carrier (SQL row, log,
# document, API response) rather than sent by the user directly.
# ---------------------------------------------------------------------------
ASI06_CONTEXT_POISONING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("context-poisoning note-to-ai carrier", re.compile(
        r"(note to ai|note to the ai|ai (note|instruction):|\[system override\]|important note:.*(ignore|forget|disregard))", re.IGNORECASE)),
    ("context-poisoning data-row injection", re.compile(
        r"(injected (as|into) (a |the )?(sql|db|database|row|record|field|comment|memo|document|log|api)|poisoned (db|database|row|record|document))", re.IGNORECASE)),
    ("context-poisoning indirect instruction", re.compile(
        r"(indirect prompt injection|cross[- ]prompt injection|xpia|prompt injection (via|through|in) (data|document|result|log))", re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# ASI07 — Insecure Inter-Agent Communication (missing auth / conditional access).
# Enriched with the MCP/A2A protocol attack-class vocabulary absorbed from
# calbebop/batesian (18 MCP rules + 17 A2A rules, each CWE-mapped). These are
# protocol-posture signals — missing auth, downgrade, IDOR, SSRF, confusion —
# distinct from the prompt-injection payloads in ASI01/ASI06.
# ---------------------------------------------------------------------------
ASI07_INTERAGENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("interagent missing conditional access", re.compile(
        r"(conditional[- ]access|inter[- ]agent (communication|trust)|service[- ]principal (sign[- ]in|auth))", re.IGNORECASE)),
    ("interagent oauth scope escalation", re.compile(
        r"(oauth (dcr|dynamic client registration|scope escalation)|scope escalation|redirect[\-_ ]uri|confused deputy)", re.IGNORECASE)),
    ("interagent audience binding bug", re.compile(
        r"(audience (matching|binding|claim)|aud[- ]substring|aud[- ]case[- ]canonical|jws algorithm confusion|alg[- ]confusion|jwt (forgery|impersonation))", re.IGNORECASE)),
    ("interagent unauthenticated tool surface", re.compile(
        r"(unauthenticated (resource|tool|prompt|task|completion|logging)|without authentication|missing (auth|authorization)|no auth|anonymous (client|access))", re.IGNORECASE)),
    ("interagent task idor", re.compile(
        r"(task idor|idor|insecure direct object|task (readable|cancel|cancellation) (across|cross)|cross[- ]principal|multi[- ]tenant (isolation|task))", re.IGNORECASE)),
    ("interagent session fixation", re.compile(
        r"(session (fixation|smuggling|id fixation|id reuse)|context (fixation|id fixation)|role injection)", re.IGNORECASE)),
    ("interagent protocol downgrade", re.compile(
        r"(protocol (version )?downgrade|version downgrade|extension downgrade|fail[- ]open|init downgrade)", re.IGNORECASE)),
    ("interagent jsonrpc batch bypass", re.compile(
        r"(json[- ]?rpc batch|batch authentication bypass|request smuggling|header[/ ]body split|split[- ]brain)", re.IGNORECASE)),
    ("interagent push ssrf", re.compile(
        r"(push notification ssrf|webhook (ssrf|control[- ]plane)|push binding|callback ssrf|metadata[- ]fetch ssrf)", re.IGNORECASE)),
    ("interagent agent card trust", re.compile(
        r"(agent[- ]?card (trust|security|disclosure|host injection)|card security unenforced|well[- ]?known host|extended agent card)", re.IGNORECASE)),
    ("interagent token replay", re.compile(
        r"(token (replay|signature)|forged token|sse resumption replay|credential (canary|leakage|reflected)|secret canary)", re.IGNORECASE)),
    ("interagent artifact tamper", re.compile(
        r"(artifact (tamper|tampering)|delegation (integrity|chain[- ]of[- ]custody)|task artifact)", re.IGNORECASE)),
]

# Order matters for attribution: a single line can trip multiple ASI classes,
# and we want the full OWASP mapping surfaced, not just the first hit.
ALL_AGENTIC_ATTACK_PATTERNS: list[tuple[str, list[tuple[str, re.Pattern[str]]]]] = [
    ("ASI01", ASI01_GOAL_HIJACK_PATTERNS),
    ("ASI02", ASI02_TOOL_MISUSE_PATTERNS),
    ("ASI03", ASI03_PRIVILEGE_ABUSE_PATTERNS),
    ("ASI04", ASI04_SUPPLY_CHAIN_PATTERNS),
    ("ASI05", ASI05_CODE_EXEC_PATTERNS),
    ("ASI06", ASI06_CONTEXT_POISONING_PATTERNS),
    ("ASI07", ASI07_INTERAGENT_PATTERNS),
]

_OWASP_LABEL = {
    "ASI01": "Agent Goal Hijack (prompt injection)",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity / Privilege Abuse",
    "ASI04": "Supply Chain / MCP Tool-Definition Mutation",
    "ASI05": "Unexpected Code Execution / Exfiltration",
    "ASI06": "Memory & Context Poisoning (XPIA)",
    "ASI07": "Insecure Inter-Agent Communication",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _is_reference_path(rel_path: str) -> bool:
    lower = rel_path.lower().replace("\\", "/")
    parts = lower.split("/")
    is_docs = any(part in {"docs", "doc", "examples", "example", "samples", "sample", "guides", "guide", "references", "reference"} for part in parts)
    is_readme = "readme" in lower
    is_test = any(part in {"tests", "test", "fixtures", "fixture"} for part in parts)
    suffix = Path(rel_path).suffix.lower()
    return is_docs or is_readme or is_test or suffix in {".md", ".rst", ".txt"} or ".example" in lower


def classify_agentic_attack_signals(line: str, rel_path: str) -> list[tuple[str, str]]:
    """Return [(signal, severity), ...] for agentic-attack indicators in a line.

    severity is "low" for reference/docs/test paths (security guides quote
    these phrases legitimately) and "high" for live code / data carriers /
    hidden-instruction surfaces. De-duplicates on signal label, keeping the
    highest severity.
    """
    is_reference = _is_reference_path(rel_path)
    signals: list[tuple[str, str]] = []

    for asi_code, patterns in ALL_AGENTIC_ATTACK_PATTERNS:
        for signal, pattern in patterns:
            if pattern.search(line):
                severity = "low" if is_reference else "high"
                # ASI04/ASI05/ASI06 signals in reference paths are still worth
                # medium (they describe actual exfil/mutation mechanics, not
                # just vocabulary).
                if is_reference and asi_code in {"ASI04", "ASI05", "ASI06"}:
                    severity = "medium"
                signals.append((f"{asi_code} {signal}", severity))

    best: dict[str, str] = {}
    for signal, severity in signals:
        prev = best.get(signal)
        if prev is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[prev]:
            best[signal] = severity
    return list(best.items())


def owasp_label(signal: str) -> str:
    """Map a signal label back to its OWASP Agentic risk class."""
    for asi_code, label in _OWASP_LABEL.items():
        if signal.startswith(asi_code):
            return label
    return "Agentic attack signal"


def summarize_agentic(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate agentic-attack findings into an OWASP-mapped summary."""
    from collections import Counter
    by_asi: Counter[str] = Counter()
    for f in findings:
        if f.get("category") != "agentic_attack":
            continue
        signal = str(f.get("signal", ""))
        asi = signal.split(" ", 1)[0] if " " in signal else signal
        by_asi[asi] += 1
    return {
        "version": "maya_agentic_attack_v0_1",
        "owasp_agentic_ref": "OWASP Top 10 for Agentic Applications (2026)",
        "asi_counts": {asi: n for asi, n in sorted(by_asi.items())},
        "asi_labels": {asi: _OWASP_LABEL.get(asi, asi) for asi in by_asi},
        "total": sum(by_asi.values()),
    }
