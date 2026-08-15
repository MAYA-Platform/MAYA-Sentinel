from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import tomllib
import unicodedata
import zipfile
from contextvars import ContextVar
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .public_safety import (
    PUBLIC_BLOCKED,
    PUBLIC_NO_SIGNAL,
    PUBLIC_REVIEW,
    PUBLIC_RISK,
    build_public_projection,
    public_state,
    sanitize_string,
)

DISCLAIMER = "Static analysis only. No runtime sandboxing performed. This is not a guarantee of safety."
FENCE = "read_only_static_analysis"

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".md", ".txt",
    ".cfg", ".ini", ".env", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".go", ".rs",
    ".java", ".kt", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".html", ".css",
    ".xml", ".gradle", ".dockerfile", ".lock", ".mod", ".sum", ".sql", ".vue", ".svelte", ".svg",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".wasm", ".pyc", ".pyo", ".class", ".jar", ".bin",
    ".dat", ".pkl", ".pickle", ".joblib", ".onnx", ".pt", ".pth", ".h5", ".msi", ".app", ".deb", ".rpm",
}

BENIGN_ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".wav", ".mp4", ".webm", ".mov",
}

BENIGN_ASSET_HOSTS = {"fonts.googleapis.com", "fonts.gstatic.com"}

MAX_FILES = 20_000
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 125 * 1024 * 1024
MAX_EXTRACTION_RATIO = 100
MAX_TEXT_SCAN_BYTES = 1_500_000
MAX_DEPENDENCY_TOKENS = 3_000
MAX_MANIFEST_DEPTH = 80
MAX_WINDOWS_ZIP_PATH = 240
MAX_ZIP_COMPONENT_BYTES = 255
DEFAULT_SCAN_DEADLINE_SECONDS = 180
MAX_FINDINGS_TOTAL = 500
MAX_FINDINGS_PER_PATH = 40
MAX_FINDING_CATEGORY_CHARS = 64
MAX_FINDING_PATH_CHARS = 240
MAX_FINDING_SIGNAL_CHARS = 180
MAX_FINDING_SNIPPET_CHARS = 240
MAX_PUBLIC_SUMMARY_ITEMS = 12
MAX_PUBLIC_DETAIL_ITEMS = 80
MAX_REPORT_FINDINGS_RENDERED = 250

_SCAN_DEADLINE: ContextVar[float | None] = ContextVar("maya_lens_scan_deadline", default=None)

SECRET_TOKEN_RE = re.compile(r"(?:sk-[A-Za-z0-9_\-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9\-]{12,}|AKIA[0-9A-Z]{12,})")
SECRET_ASSIGNMENT_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*['\"]?([^'\"\s#]+)")
BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{160,}={0,2})")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
ARCHIVE_EXTENSIONS = {".zip", ".gz", ".tgz", ".7z", ".rar", ".jar", ".war", ".ear"}
MODEL_REVIEW_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".onnx", ".safetensors", ".h5", ".keras"}
WINDOWS_DEVICE_NAMES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}

PROCESS_PATTERNS = [
    ("os.system", re.compile(r"\bos\.system\s*\(")),
    ("subprocess", re.compile(r"\bsubprocess\.(run|call|Popen|check_call|check_output)\s*\(")),
    ("exec/eval", re.compile(r"\b(exec|eval)\s*\(")),
    ("node child_process", re.compile(r"child_process|\bexecSync\s*\(|\bspawn\s*\(")),
    ("pipe-to-shell", re.compile(r"(curl|wget).{0,80}(\||bash|sh|powershell)", re.IGNORECASE)),
    ("reverse shell", re.compile(r"nc\s+-e|/dev/tcp/|Invoke-PowerShellTcp", re.IGNORECASE)),
]

NETWORK_PATTERNS = [
    ("hardcoded URL", URL_RE),
    ("python http client", re.compile(r"\b(requests|urllib|http\.client|socket)\b")),
    ("browser/node network", re.compile(r"\b(fetch|axios|XMLHttpRequest|WebSocket)\s*\(?")),
    ("cli downloader", re.compile(r"\b(curl|wget)\b", re.IGNORECASE)),
]

LOCKFILE_DEPENDENCY_RE = re.compile(r'^(?:"|\')?(?P<name>@?[^@"\': ]+(?:/[^@"\': ]+)?)@')
GRADLE_DEPENDENCY_RE = re.compile(r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly)\b")
POM_DEPENDENCY_RE = re.compile(r"<dependency>.*?<groupId>(?P<group>[^<]+)</groupId>.*?<artifactId>(?P<artifact>[^<]+)</artifactId>.*?</dependency>", re.DOTALL)


FILESYSTEM_PATTERNS = [
    ("credential path", re.compile(r"(\.ssh|\.aws|\.hermes|id_rsa|authorized_keys|credentials|AppData|Startup)", re.IGNORECASE)),
    ("persistence command", re.compile(r"(schtasks|crontab|systemctl|launchctl|reg\s+add)", re.IGNORECASE)),
    ("dangerous deletion", re.compile(r"rm\s+-rf\s+(/|~)|mkfs\.|dd\s+if=", re.IGNORECASE)),
    ("permission escalation", re.compile(r"\b(sudo|chmod\s+777|chown)\b", re.IGNORECASE)),
]

TELEMETRY_PATTERNS = [
    ("analytics SDK", re.compile(r"(google-analytics|gtag\s*\(|mixpanel|@segment/analytics|segment\.com|analytics\.track|posthog|amplitude|firebase/analytics|datadog|sentry)", re.IGNORECASE)),
    ("fingerprinting", re.compile(r"(fingerprint|canvas\.toDataURL|navigator\.plugins|navigator\.userAgent)", re.IGNORECASE)),
]

# --- Phishing / brand-impersonation signal surface (static only) ---
# Built from the 2026-08-15 HERMES-TOKEN / hermes-agent.icu phishing campaign
# investigation and standard phishing-abuse knowledge. All checks are pure
# pattern matching on repo text; no network calls, no DNS, no live reputation.
# False-positive control: brand impersonation requires a known brand token on
# a non-canonical host, and documentation references stay advisory unless the
# signal appears in code/HTML with executable or credential-harvest intent.

SHORTLINK_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "t.ly", "is.gd",
    "cutt.ly", "rebrand.ly", "s.id", "shorturl.at", "ow.ly", "buff.ly",
    "rb.gy", "tiny.cc", "soo.gd", "tny.im", "shorte.st", "adf.ly", "bc.vc",
    "qr.ae", "v.gd", "tiny.one", "lnkd.in", "surl.li", "urlzs.com", "cutt.us",
}

# Cheap / abuse-prone TLDs that phishing and scam infrastructure favor.
SUSPICIOUS_TLDS = {
    "icu", "top", "gq", "ml", "xyz", "cf", "tk", "ga", "info", "buzz",
    "club", "online", "site", "live", "rest", "monster", "download",
    "country", "stream", "gdn", "vip", "work", "party", "racing", "review",
    "kim", "loan", "win", "bid", "click", "link", "date", "men", "science",
    "zip", "mov", "pharmacy", "accountant", "loan", "credit", "casino",
    "poker", "bet", "cricket", "xyz", "cyou", "shop", "store", "sale",
    "gdn", "quest", "surf", "uno", "space", "website", "fun", "digital",
}

# Known brands scammers impersonate, mapped to their canonical host suffixes.
# host == canonical -> benign. host contains brand but is NOT canonical -> flag.
BRAND_CANONICAL_HOSTS = {
    "hermes": {"hermes-agent.nousresearch.com", "nousresearch.com"},
    "nousresearch": {"nousresearch.com"},
    "openai": {"openai.com"},
    "anthropic": {"anthropic.com", "claude.ai"},
    "claude": {"claude.ai", "anthropic.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "googlesyndication.com"},
    "gmail": {"gmail.com", "google.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "msn.com"},
    "outlook": {"outlook.com", "microsoft.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
    "telegram": {"telegram.org", "t.me"},
    "whatsapp": {"whatsapp.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "aws.amazon.com", "amazonaws.com"},
    "aws": {"amazonaws.com", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "binance": {"binance.com"},
    "github": {"github.com", "github.io"},
    "gitlab": {"gitlab.com"},
    "slack": {"slack.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "riotgames": {"riotgames.com"},
    "epicgames": {"epicgames.com"},
    "roblox": {"roblox.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "venmo": {"venmo.com"},
    "cashapp": {"cash.app", "cashapp.com"},
    "zelle": {"zellepay.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
}

# Ad-fraud / scam / click-fraud tracking + distribution stacks seen on phishing
# and malware-bait domains (e.g. hermes-agent.icu: Yandex Metrika + mail.ru
# counter + digitalcaramel). Distinct from legit analytics (TELEMETRY_PATTERNS).
SCAM_TRACKING_PATTERNS = [
    ("scam ad/redirect stack", re.compile(r"(digitalcaramel|clickadu|propellerads|popcash|popads|adsterra|exoclick|juicyads|clickaine)", re.IGNORECASE)),
    ("yandex metrika on phishing surface", re.compile(r"mc\.yandex\.ru|metrika/tag\.js|yandex\.ru/metrika", re.IGNORECASE)),
    ("mail.ru counter", re.compile(r"top-fwz1\.mail\.ru|mail\.ru/js/code\.js", re.IGNORECASE)),
    ("aggressive ad network", re.compile(r"pagead2\.googlesyndication\.com.*adsbygoogle|adsbygoogle\.js", re.IGNORECASE)),
    ("bot-detection / anti-scrape stack", re.compile(r"openfpcdn\.io/botd|fingerprintjs", re.IGNORECASE)),
]

# Credential harvesting / wallet drainer / fake-verification language.
PHISHING_TEXT_PATTERNS = [
    ("credential harvest language", re.compile(r"(verify your (account|identity|login)|sign in to verify|confirm your password to continue|your account (has been )?(suspended|locked|restricted).{0,60}click|update your payment details|unusual (login|activity).{0,60}verify)", re.IGNORECASE)),
    ("wallet drainer language", re.compile(r"(connect your wallet.{0,80}(claim|mint|airdrop)|approve (this )?(contract|transaction).{0,80}claim|seed phrase.{0,80}(verify|recover|confirm)|recovery phrase.{0,80}(never|enter))", re.IGNORECASE)),
    ("fake airdrop/presale", re.compile(r"(free (airdrop|presale|token).{0,80}(claim|join)|airdrop.{0,60}(claim|distribution).{0,60}wallet)", re.IGNORECASE)),
    ("token scam contract", re.compile(r"(approve.{0,40}spend.{0,40}unlimited|setAllowance.{0,60}max|transferFrom.{0,80}wallet)", re.IGNORECASE)),
    ("fake support/survey bait", re.compile(r"(claim your (reward|prize|bonus).{0,80}(login|connect|enter)|you have been selected.{0,80}(claim|collect|redeem))", re.IGNORECASE)),
]

# Data exfiltration / callback endpoints commonly used by malware and scam bait.
EXFIL_ENDPOINT_PATTERNS = [
    ("discord webhook exfil", re.compile(r"discord(app)?\.com/api/webhooks/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+", re.IGNORECASE)),
    ("telegram bot token / channel", re.compile(r"t\.me/[A-Za-z0-9_]{3,}|api\.telegram\.org/bot\d{6,}:[A-Za-z0-9_\-]{20,}", re.IGNORECASE)),
    ("paste/transfer exfil", re.compile(r"(pastebin\.com|transfer\.sh|file\.io|0x0\.st|tmpfiles\.org|anonfiles\.com|katfile)", re.IGNORECASE)),
    ("webhook/callback collector", re.compile(r"(webhook\.site|requestbin\.com|pipedream\.net|beeceptor\.com|hookbin\.com|mocky\.io)", re.IGNORECASE)),
    ("crypto payment demand", re.compile(r"send (btc|eth|usdt).{0,60}(to|this).{0,20}(address|wallet)|pay.{0,30}(ransom|fee).{0,40}(btc|eth|bitcoin|ethereum)", re.IGNORECASE)),
]

AI_COMPONENT_RULES = [
    ("agent_instruction", re.compile(r"(^|/)(AGENTS\.md|CLAUDE\.md|\.cursorrules|\.cursor/rules|\.agents/|\.claude/skills/|skills?/SKILL\.md)", re.IGNORECASE)),
    ("mcp_server", re.compile(r"(^|/)(mcp\.json|claude_desktop_config\.json|.*mcp.*\.(json|yaml|yml|toml|py|js|ts))$", re.IGNORECASE)),
    ("workflow_automation", re.compile(r"(^|/)\.github/workflows/|(^|/)(Dockerfile|docker-compose\.ya?ml|Makefile)$", re.IGNORECASE)),
    ("model_or_prompt_asset", re.compile(r"(^|/)(prompts?|models?|evals?|benchmarks?|fixtures?)/|\.(gguf|safetensors|onnx|pt|pth|prompt|jinja|j2)$", re.IGNORECASE)),
    ("security_scanner", re.compile(r"(scan|scanner|audit|sbom|bom|cve|vuln|remediation|sast|dependency|license)", re.IGNORECASE)),
]

REMEDIATION_BY_CATEGORY = {
    "archive_safety": "Keep the archive static-only, preserve the blocked receipt, and only inspect a trusted sanitized export if a human explicitly wants deeper review.",
    "credential": "Remove the secret from source, rotate the credential if real, and rerun Repo Brief before execution.",
    "install_hook": "Review install hooks manually; do not install until the hook is understood and approved.",
    "process": "Review command/process execution paths and require manual safety approval before running.",
    "filesystem": "Review filesystem/persistence behavior and keep execution blocked until scoped.",
    "binary": "Treat native/executable artifacts as review-required; preserve statically, do not run by default.",
    "network": "Review outbound endpoints and data flow before granting network execution.",
    "dependency": "Review dependency manifests and pin/lock behavior before install.",
    "obfuscation": "Inspect encoded/large generated content manually before trusting the repo.",
    "intrusiveness": "Review telemetry/fingerprinting behavior before using in a user-facing or local runtime surface.",
    "phishing": "Treat shortlink, lookalike-domain, credential-harvest, wallet-drainer, or exfil-endpoint signals as high-priority review. Verify the destination of every shortened/lookalike URL before trusting or executing anything from the repo. Do not run installers or connect wallets from a repo carrying these signals.",
}

ADVISORY_URGENCY_BY_DECISION = {
    "block_review_before_any_run": "hold",
    "deep_artifact_escalation": "deep_review",
    "advisory_enrichment_review": "enrich",
    "standard_static_review": "review",
}

AGENTIC_POLICY_GUIDANCE = {
    "mcp_server": "Verify least privilege, tool poisoning resistance, and explicit server allowlists before enabling any MCP surface.",
    "agent_instruction": "Review hidden policy changes, correction handling, and tool-scope claims before importing agent behavior.",
    "workflow_automation": "Check outbound action scope, approval gates, and whether the workflow implies acting for a user without explicit permission.",
    "model_or_prompt_asset": "Inspect prompts/evals/model assets for prompt injection, hidden routing assumptions, and data-leakage paths.",
    "security_scanner": "Treat scanner output as advisory signal, not proof of safety; confirm what it actually checks before trusting its verdicts.",
}

SECURITY_TOOL_SURFACE_RULES = [
    {
        "id": "ci_security_workflows",
        "label": "CI security workflow",
        "patterns": [r"\.github/workflows/", r"\b(codeql|snyk|semgrep|trivy|gitleaks|dependency[-_ ]review|security[-_ ]scan)\b"],
        "recommended_action": "Treat CI security workflow patterns as packaging guidance; do not install upstream actions until scopes and secrets are reviewed.",
    },
    {
        "id": "secret_scanning",
        "label": "Secret scanning surface",
        "patterns": [r"\b(secret[-_ ]?scan|credential[-_ ]?scan|gitleaks|detect[-_ ]secrets|trufflehog|cli[-_ ]extension[-_ ]secrets)\b"],
        "recommended_action": "Use secret-scanning language to improve redacted reporting and never expose raw secret values in user-facing output.",
    },
    {
        "id": "api_graphql_surface",
        "label": "API / GraphQL review surface",
        "patterns": [r"\b(api[-_ ]?hunter|openapi|swagger|graphql|gqls|schema introspection|endpoint discovery)\b"],
        "recommended_action": "Classify API/GraphQL discovery as review evidence; live endpoint probing needs explicit target scope.",
    },
    {
        "id": "dependency_graph_surface",
        "label": "Dependency graph surface",
        "patterns": [r"\b(dep[-_ ]?graph|dependency graph|sbom|software bill of materials|package graph|cli[-_ ]extension[-_ ]dep[-_ ]graph)\b"],
        "recommended_action": "Prefer dependency-graph extraction as static enrichment before any package install or transitive audit claim.",
    },
    {
        "id": "mcp_agent_exposure_scan",
        "label": "MCP / agent exposure scan",
        "patterns": [r"\b(mcp|a2a|agent card|agent exposure|llm interface|open llm|ollama|vllm|llama\.cpp|litellm)\b"],
        "recommended_action": "Gate MCP/A2A/LLM exposure scanning behind manual target scope and permission receipts.",
    },
    {
        "id": "live_target_scan",
        "label": "Live target scan surface",
        "patterns": [r"\b(cidr|port scan|scan target|target url|recon|penetration testing|pentest|vulnerability scan)\b"],
        "recommended_action": "Treat live-target scan behavior as approval-gated; Repo Brief may analyze the repo, not run scans against targets.",
    },
]

COMPILED_SECURITY_TOOL_SURFACE_RULES = [
    {**rule, "compiled": [re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]]}
    for rule in SECURITY_TOOL_SURFACE_RULES
]


ACTION_BOUNDARY_RULES = [
    {
        "id": "financial_action",
        "label": "Financial action",
        "patterns": [r"\brefunds?\b", r"\bpayments?\b", r"\bcharge\b", r"\bbilling\b", r"\binvoice\b", r"\bpayout\b"],
        "recommended_action": "Require explicit approval before any money movement, refund, charge, payout, or billing change.",
    },
    {
        "id": "vendor_bank_change",
        "label": "Vendor bank change",
        "patterns": [r"vendor bank", r"bank account", r"routing number", r"wire transfer", r"payout account"],
        "recommended_action": "Treat vendor bank or payout changes as manual-review-only authority transfers.",
    },
    {
        "id": "access_control",
        "label": "Access control",
        "patterns": [r"grant access", r"revoke access", r"admin role", r"user role", r"invite user", r"permission(s)?"],
        "recommended_action": "Review identity, role, and permission changes before allowing an agent to act.",
    },
    {
        "id": "data_export",
        "label": "Data export",
        "patterns": [r"export data", r"download records", r"customer data", r"resident data", r"\bpii\b", r"dump database"],
        "recommended_action": "Require scope, redaction, and explicit approval before data export or customer/resident data handling.",
    },
    {
        "id": "record_modification",
        "label": "Record modification",
        "patterns": [r"edit (customer |resident |)?records?", r"update (customer |resident |)?records?", r"delete (customer |resident |)?records?", r"approve lease", r"work orders?"],
        "recommended_action": "Preview record changes and preserve an action receipt before committing writes.",
    },
    {
        "id": "external_communication",
        "label": "External communication",
        "patterns": [r"send email", r"send sms", r"text message", r"notify (customer|resident|user|vendor)", r"slack", r"webhook"],
        "recommended_action": "Require human confirmation before outbound messages or third-party notifications.",
    },
    {
        "id": "deployment_or_release",
        "label": "Deployment or release",
        "patterns": [r"\bdeploy\b", r"production", r"release workflow", r"publish", r"ship to prod"],
        "recommended_action": "Keep deployment/release behavior approval-gated and receipt-backed.",
    },
    {
        "id": "destructive_filesystem",
        "label": "Destructive filesystem",
        "patterns": [r"rm\s+-rf", r"delete files?", r"wipe", r"remove directory", r"destructive"],
        "recommended_action": "Block destructive filesystem actions unless a human scopes the exact target and rollback path.",
    },
    {
        "id": "credential_or_secret",
        "label": "Credential or secret access",
        "patterns": [r"api[_-]?key", r"secret", r"token", r"password", r"credential", r"private key"],
        "recommended_action": "Redact secrets in reports and require review before any credential access or secret-handling workflow.",
    },
    {
        "id": "tool_execution",
        "label": "Tool execution",
        "patterns": [r"postinstall", r"subprocess", r"os\.system", r"execsync", r"shell command", r"tool call", r"mcp server"],
        "recommended_action": "Keep tool execution behind static review, least-privilege scopes, and explicit approval for high-authority actions.",
    },
]

COMPILED_ACTION_BOUNDARY_RULES = [
    {**rule, "compiled": [re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]]}
    for rule in ACTION_BOUNDARY_RULES
]

@dataclass
class ZipPolicy:
    max_files: int = MAX_FILES
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES
    max_single_file_bytes: int = MAX_SINGLE_FILE_BYTES
    max_ratio: int = MAX_EXTRACTION_RATIO


class ZipSafetyError(RuntimeError):
    """Raised when a ZIP cannot be inspected safely."""


class ScanDeadlineExceeded(ZipSafetyError):
    """Raised when static scanner work cooperatively stops at its deadline."""


class FindingList(list):
    def __init__(self, items: list[dict[str, Any]] | None = None):
        super().__init__()
        self.seen: set[tuple[Any, ...]] = set()
        self.path_counts: Counter[str] = Counter()
        self.overflow_added = False
        if items:
            for item in items:
                add_finding(
                    self,
                    category=str(item.get("category", "")),
                    severity=str(item.get("severity", "info")),
                    path=str(item.get("path", "")),
                    signal=str(item.get("signal", "")),
                    line=item.get("line"),
                    snippet=str(item.get("snippet", "")),
                )


def _truncate(value: Any, limit: int) -> str:
    text = sanitize_string(str(value or ""))
    return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."


def check_scan_deadline(stage: str = "scan") -> None:
    deadline = _SCAN_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise ScanDeadlineExceeded(f"Scan deadline exceeded during {stage}.")


def _overflow_finding(reason: str) -> dict[str, Any]:
    return {
        "category": "scanner_budget",
        "severity": "medium",
        "path": "[scanner-budget]",
        "line": None,
        "signal": "finding output budget reached",
        "snippet": _truncate(reason, MAX_FINDING_SNIPPET_CHARS),
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            check_scan_deadline("source hashing")
            h.update(chunk)
    return h.hexdigest()


def normalize_zip_name(name: str) -> PurePosixPath:
    clean = name.replace("\\", "/")
    if clean.startswith("//") or name.startswith("\\\\"):
        raise ZipSafetyError(f"ZIP path UNC ambiguity blocked: {name!r}")
    if not clean or clean.startswith("/"):
        raise ZipSafetyError(f"ZIP path traversal/absolute path blocked: {name!r}")
    if re.match(r"^[A-Za-z]:", clean):
        raise ZipSafetyError(f"ZIP path traversal/drive path blocked: {name!r}")
    p = PurePosixPath(clean)
    if any(part in ("", ".", "..") for part in p.parts):
        raise ZipSafetyError(f"ZIP path traversal blocked: {name!r}")
    if len(clean) > MAX_WINDOWS_ZIP_PATH:
        raise ZipSafetyError(f"ZIP Windows path length blocked: {name!r}")
    for part in p.parts:
        if len(part.encode("utf-8")) > MAX_ZIP_COMPONENT_BYTES:
            raise ZipSafetyError(f"ZIP component length blocked: {name!r}")
        if ":" in part:
            raise ZipSafetyError(f"ZIP NTFS alternate data stream name blocked: {name!r}")
        if part.endswith((" ", ".")):
            raise ZipSafetyError(f"ZIP trailing dot/space component blocked: {name!r}")
        base = part.split(".", 1)[0].lower()
        if base in WINDOWS_DEVICE_NAMES:
            raise ZipSafetyError(f"ZIP Windows device name blocked: {name!r}")
    return p


def _zip_canonical_key(path: PurePosixPath) -> str:
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def validate_zip(zip_path: Path, policy: ZipPolicy) -> list[zipfile.ZipInfo]:
    check_scan_deadline("ZIP validation")
    if not zipfile.is_zipfile(zip_path):
        raise ZipSafetyError("Input is not a valid ZIP archive.")
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > policy.max_files:
            raise ZipSafetyError(f"ZIP bomb behavior blocked: {len(infos)} files exceeds {policy.max_files}.")
        total_size = 0
        exact_names: set[str] = set()
        canonical_names: dict[str, str] = {}
        directories: set[str] = set()
        files: set[str] = set()
        for info in infos:
            check_scan_deadline("ZIP validation")
            if info.flag_bits & 0x1:
                raise ZipSafetyError(f"Encrypted ZIP member blocked: {info.filename}")
            if info.filename in exact_names:
                raise ZipSafetyError(f"ZIP duplicate member blocked: {info.filename!r}")
            exact_names.add(info.filename)
            normalized = normalize_zip_name(info.filename)
            canonical = _zip_canonical_key(normalized)
            previous = canonical_names.get(canonical)
            if previous and previous != info.filename:
                raise ZipSafetyError(f"ZIP canonical path collision blocked: {previous!r} vs {info.filename!r}")
            canonical_names[canonical] = info.filename
            parent = ""
            for part in canonical.split("/")[:-1]:
                parent = f"{parent}/{part}" if parent else part
                directories.add(parent)
                if parent in files:
                    raise ZipSafetyError(f"ZIP file/directory collision blocked: {info.filename!r}")
            if info.is_dir():
                directories.add(canonical)
                if canonical in files:
                    raise ZipSafetyError(f"ZIP file/directory collision blocked: {info.filename!r}")
            else:
                files.add(canonical)
                if canonical in directories and canonical != "":
                    raise ZipSafetyError(f"ZIP file/directory collision blocked: {info.filename!r}")
            if is_zip_symlink(info):
                raise ZipSafetyError(f"Symlink escape blocked in ZIP member: {info.filename}")
            total_size += info.file_size
            if info.file_size > policy.max_single_file_bytes:
                raise ZipSafetyError(f"Large file blocked before extraction: {info.filename} ({info.file_size} bytes).")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > policy.max_ratio and info.file_size > 10 * 1024 * 1024:
                raise ZipSafetyError(f"ZIP bomb ratio blocked for member: {info.filename}")
        if total_size > policy.max_uncompressed_bytes:
            raise ZipSafetyError(f"ZIP bomb behavior blocked: uncompressed size {total_size} exceeds policy.")
        return infos


def safe_extract(zip_path: Path, destination: Path, policy: ZipPolicy) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    try:
        infos = validate_zip(zip_path, policy)
        stats: dict[str, Any] = {
            "file_count": 0,
            "total_extracted_bytes": 0,
            "files": [],
            "total_declared_uncompressed_bytes": sum(info.file_size for info in infos),
            "total_declared_compressed_bytes": sum(info.compress_size for info in infos),
            "max_compression_ratio": 0,
        }
        with zipfile.ZipFile(zip_path) as zf:
            for info in infos:
                check_scan_deadline("ZIP extraction")
                rel = normalize_zip_name(info.filename)
                if info.compress_size:
                    stats["max_compression_ratio"] = max(stats["max_compression_ratio"], round(info.file_size / max(info.compress_size, 1), 2))
                target = destination / Path(*rel.parts)
                resolved = target.resolve()
                root = destination.resolve()
                if root not in resolved.parents and resolved != root:
                    raise ZipSafetyError(f"ZIP path traversal blocked at extraction: {info.filename}")
                if info.is_dir():
                    resolved.mkdir(parents=True, exist_ok=True)
                    continue
                resolved.parent.mkdir(parents=True, exist_ok=True)
                copied = 0
                try:
                    with zf.open(info) as src, resolved.open("wb") as dst:
                        for chunk in iter(lambda: src.read(1024 * 1024), b""):
                            check_scan_deadline("ZIP extraction")
                            copied += len(chunk)
                            total_after = stats["total_extracted_bytes"] + copied
                            if copied > policy.max_single_file_bytes or copied > info.file_size:
                                raise ZipSafetyError(f"Actual extracted bytes exceeded file budget for ZIP member: {info.filename}")
                            if total_after > policy.max_uncompressed_bytes:
                                raise ZipSafetyError(f"Actual extracted bytes exceeded total ZIP budget at member: {info.filename}")
                            dst.write(chunk)
                except RuntimeError as exc:
                    if "encrypt" in str(exc).lower() or "password" in str(exc).lower():
                        raise ZipSafetyError(f"Encrypted ZIP member blocked: {info.filename}") from exc
                    raise
                except (zipfile.BadZipFile, EOFError) as exc:
                    raise ZipSafetyError(f"Corrupt or truncated ZIP member blocked: {info.filename}") from exc
                if copied != info.file_size:
                    raise ZipSafetyError(f"Truncated ZIP member blocked: {info.filename}")
                stats["file_count"] += 1
                stats["total_extracted_bytes"] += copied
                if len(stats["files"]) < 100:
                    stats["files"].append({"path": rel.as_posix(), "bytes": copied})
        safe_extract.last_stats = stats
        return destination
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {"dockerfile", "makefile", "license", "readme"}:
        return True
    try:
        with path.open("rb") as f:
            sample = f.read(4096)
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def inventory_tree(root: Path) -> dict[str, Any]:
    total_bytes = 0
    file_count = 0
    dir_count = 0
    ext_counts: Counter[str] = Counter()
    largest: list[dict[str, Any]] = []
    special = {"readme": False, "license": False, "git_metadata": False, "github_workflows": False}

    for current, dirs, files in os.walk(root):
        check_scan_deadline("inventory")
        dir_count += len(dirs)
        rel_current = Path(current).relative_to(root)
        if ".git" in dirs:
            special["git_metadata"] = True
        if rel_current.as_posix().startswith(".github"):
            special["github_workflows"] = True
        for filename in files:
            path = Path(current) / filename
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            total_bytes += size
            file_count += 1
            suffix = path.suffix.lower() or "[no extension]"
            ext_counts[suffix] += 1
            lower = filename.lower()
            if lower.startswith("readme"):
                special["readme"] = True
            if lower.startswith("license") or lower == "copying":
                special["license"] = True
            largest.append({"path": path.relative_to(root).as_posix(), "bytes": size})

    largest = sorted(largest, key=lambda item: item["bytes"], reverse=True)[:10]
    return {
        "file_count": file_count,
        "dir_count": dir_count,
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "extensions": dict(ext_counts.most_common(25)),
        "largest_files": largest,
        "special": special,
    }


def empty_inventory() -> dict[str, Any]:
    return {
        "file_count": 0,
        "dir_count": 0,
        "total_bytes": 0,
        "total_mb": 0,
        "extensions": {},
        "largest_files": [],
        "special": {"readme": False, "license": False, "git_metadata": False, "github_workflows": False},
    }


def empty_dependencies() -> dict[str, Any]:
    return {
        "manifest_files": [],
        "lockfiles": [],
        "direct_count": 0,
        "dependencies": [],
        "install_hooks": [],
    }


def empty_governance_surface() -> dict[str, Any]:
    return {
        "version": "maya_governance_surface_v0_1",
        "counts": {
            "approval_docs": 0,
            "security_policy_files": 0,
            "contributing_guides": 0,
            "changelog_files": 0,
            "release_workflows": 0,
            "docs_workflows": 0,
            "issue_templates": 0,
            "codeowners_files": 0,
        },
        "approval_docs": [],
        "workflow_signals": [],
        "maintenance_signals": [],
    }


def empty_security_tool_surface() -> dict[str, Any]:
    return {
        "version": "maya_security_tool_surface_v0_1",
        "counts": {
            "ci_security_workflows": 0,
            "secret_scanning": 0,
            "api_graphql_surface": 0,
            "dependency_graph_surface": 0,
            "mcp_agent_exposure_scan": 0,
            "live_target_scan": 0,
        },
        "signals": [],
        "recommended_review_actions": [
            "Keep scanner/integration repos static-only until a human scopes the target and action boundary.",
            "Treat API, GraphQL, MCP, and secret-scanning surfaces as review evidence, not permission to run tools.",
        ],
        "pattern_sources": [
            "7anX/AgentScan MCP/A2A/LLM exposure scanner framing",
            "Teycir/ApiHunter API endpoint discovery surface",
            "omkoli/GQLS-CLI GraphQL schema/endpoint review surface",
            "snyk/actions CI security workflow packaging",
            "snyk/cli-extension-secrets and snyk/cli-extension-dep-graph extension-surface signals",
        ],
    }


def infer_identity_from_zip(zip_path: Path) -> str:
    stem = zip_path.stem
    if "__" in stem:
        owner, repo = stem.split("__", 1)
        if owner and repo:
            return f"{owner}/{repo}"
    return stem.replace("_", "-")


def redact_line(line: str) -> str:
    line = SECRET_TOKEN_RE.sub("[REDACTED_TOKEN]", line)
    line = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", line)
    line = sanitize_string(line)
    if len(line) > MAX_FINDING_SNIPPET_CHARS:
        return line[: MAX_FINDING_SNIPPET_CHARS - 3] + "..."
    return line


def add_finding(findings: list[dict[str, Any]], *, category: str, severity: str, path: str, signal: str, line: int | None = None, snippet: str = "") -> None:
    category = _truncate(category, MAX_FINDING_CATEGORY_CHARS)
    severity = _truncate(severity or "info", 24)
    path = _truncate(path, MAX_FINDING_PATH_CHARS)
    signal = _truncate(signal, MAX_FINDING_SIGNAL_CHARS)
    evidence = redact_line(_truncate(snippet, MAX_FINDING_SNIPPET_CHARS)) if snippet else ""
    key = (category, severity, path, line, signal, evidence)

    seen = getattr(findings, "seen", None)
    if seen is None:
        seen = {
            (item.get("category"), item.get("severity"), item.get("path"), item.get("line"), item.get("signal"), item.get("snippet", ""))
            for item in findings
        }
    if key in seen:
        return

    path_counts = getattr(findings, "path_counts", None)
    if path_counts is None:
        path_counts = Counter(str(item.get("path", "")) for item in findings if item.get("category") != "scanner_budget")
    overflow_added = bool(getattr(findings, "overflow_added", False)) or any(item.get("category") == "scanner_budget" for item in findings)

    def add_overflow(reason: str) -> None:
        nonlocal overflow_added
        if overflow_added:
            return
        if len(findings) >= MAX_FINDINGS_TOTAL:
            return
        marker = _overflow_finding(reason)
        findings.append(marker)
        overflow_added = True
        if hasattr(findings, "overflow_added"):
            findings.overflow_added = True
        if hasattr(findings, "seen"):
            findings.seen.add((marker["category"], marker["severity"], marker["path"], marker["line"], marker["signal"], marker["snippet"]))

    if path_counts[path] >= MAX_FINDINGS_PER_PATH:
        add_overflow(f"Additional findings were suppressed after {MAX_FINDINGS_PER_PATH} retained finding(s) for one path.")
        return
    if len(findings) >= MAX_FINDINGS_TOTAL - (0 if overflow_added else 1):
        add_overflow(f"Additional findings were suppressed after the {MAX_FINDINGS_TOTAL} finding output cap was reached.")
        return

    findings.append({
        "category": category,
        "severity": severity,
        "path": path,
        "line": line,
        "signal": signal,
        "snippet": evidence,
    })
    if hasattr(findings, "seen"):
        findings.seen.add(key)
    if hasattr(findings, "path_counts"):
        findings.path_counts[path] += 1


def bound_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return list(FindingList(items))


def hardcoded_url_severity(line: str, rel_path: str) -> str | None:
    """Classify plain URLs without treating normal open-source/docs/assets as scary."""
    lower = line.lower()
    suffix = Path(rel_path).suffix.lower()
    if "data:image" in lower or "data:font" in lower or "xmlns='http://www.w3.org" in lower or 'xmlns="http://www.w3.org' in lower:
        return None
    urls = URL_RE.findall(line)
    hosts = set()
    for url in urls:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if parsed.netloc:
            hosts.add(parsed.netloc.lower().split("@")[-1].split(":")[0])
    if not urls:
        return None
    if suffix in {".md", ".txt"}:
        return "info"
    if suffix in {".html", ".css", ".svg"}:
        if hosts and hosts.issubset(BENIGN_ASSET_HOSTS):
            return "info"
        if any(token in lower for token in ("rel=\"stylesheet\"", "rel='stylesheet'", "rel=\"preconnect\"", "rel='preconnect'", "background-image", "img src", "href=\"#")):
            return "low"
    return "medium"


def _host_tld(host: str) -> str | None:
    """Return the registrable TLD-ish tail of a host (last label or last two for ccTLD combos)."""
    labels = [label for label in host.rstrip(".").split(".") if label]
    if len(labels) >= 2:
        return labels[-1].lower()
    return labels[-1].lower() if labels else None


def _host_suffix_matches(host: str, canonical_set: set[str]) -> bool:
    """True if host equals or ends with any canonical host suffix (dot-bounded)."""
    host = host.lower().rstrip(".")
    for canon in canonical_set:
        canon = canon.lower().rstrip(".")
        if host == canon:
            return True
        if host.endswith("." + canon):
            return True
    return False


def classify_phishing_signals(line: str, rel_path: str) -> list[tuple[str, str]]:
    """Return [(signal, severity), ...] for phishing/impersonation indicators.

    Static-only. Shortlink/lookalike signals are advisory in docs but escalate
    in code/HTML. Brand impersonation requires a known brand token on a
    non-canonical host. Exfil endpoints and wallet-drainer language are
    high-severity wherever they appear (outside obvious security-reference docs).
    """
    lower = line.lower()
    suffix = Path(rel_path).suffix.lower()
    is_docs = suffix in {".md", ".rst", ".txt"} or "readme" in rel_path.lower() or "/docs/" in f"/{rel_path.lower()}" or "/examples/" in f"/{rel_path.lower()}"
    is_reference = is_docs or "test" in rel_path.lower() or "fixture" in rel_path.lower() or ".example" in rel_path.lower()

    signals: list[tuple[str, str]] = []

    # 1. Shortlink domains hiding destinations.
    for url in URL_RE.findall(lower):
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0]
        if not host:
            continue
        if any(host == dom or host.endswith("." + dom) for dom in SHORTLINK_DOMAINS):
            signals.append(("shortlink hides destination", "low" if is_docs else "high"))
            continue
        tld = _host_tld(host)
        if tld in SUSPICIOUS_TLDS:
            signals.append(("suspicious TLD (scam-favored)", "low" if is_docs else "medium"))
        # 2. Brand impersonation: known brand token on a non-canonical host.
        for brand, canonical in BRAND_CANONICAL_HOSTS.items():
            if brand in host and not _host_suffix_matches(host, canonical):
                signals.append(("brand-impersonation lookalike host", "medium" if is_docs else "high"))
                break

    # 3. Scam tracking / ad-fraud stacks (HTML/JS only by nature, but scan any text).
    for signal, pattern in SCAM_TRACKING_PATTERNS:
        if pattern.search(lower):
            signals.append((signal, "medium"))

    # 4. Credential-harvest / wallet-drainer / fake-verification language.
    for signal, pattern in PHISHING_TEXT_PATTERNS:
        if pattern.search(lower):
            signals.append((signal, "low" if is_reference else "high"))

    # 5. Exfiltration / callback endpoints.
    for signal, pattern in EXFIL_ENDPOINT_PATTERNS:
        if pattern.search(lower):
            signals.append((signal, "low" if is_reference else "high"))

    # De-dup, keep highest severity per signal label.
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    best: dict[str, str] = {}
    for signal, severity in signals:
        prev = best.get(signal)
        if prev is None or rank[severity] > rank[prev]:
            best[signal] = severity
    return list(best.items())


def read_bounded_text(path: Path, rel: str, findings: list[dict[str, Any]], *, label: str = "manifest") -> str | None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        add_finding(findings, category="filesystem", severity="medium", path=rel, signal=f"{label} unreadable", snippet=str(exc))
        return None
    if size > MAX_TEXT_SCAN_BYTES:
        add_finding(findings, category="dependency", severity="medium", path=rel, signal=f"oversized {label} byte budget exceeded", snippet=f"{size} bytes")
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        add_finding(findings, category="filesystem", severity="medium", path=rel, signal=f"{label} read failed", snippet=str(exc))
        return None


def structural_depth(value: Any, *, limit: int = MAX_MANIFEST_DEPTH) -> int:
    stack: list[tuple[Any, int]] = [(value, 1)]
    max_depth = 0
    while stack:
        item, depth = stack.pop()
        max_depth = max(max_depth, depth)
        if depth > limit:
            return depth
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return max_depth


def parse_json_object_file(path: Path, root: Path, findings: list[dict[str, Any]], *, label: str) -> dict[str, Any] | None:
    check_scan_deadline(f"{label} parsing")
    rel = path.relative_to(root).as_posix()
    text = read_bounded_text(path, rel, findings, label=label)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except Exception as exc:
        add_finding(findings, category="dependency", severity="medium", path=rel, signal=f"{label} parse failed", snippet=str(exc))
        return None
    if not isinstance(data, dict):
        add_finding(findings, category="dependency", severity="medium", path=rel, signal=f"{label} root type requires review", snippet=type(data).__name__)
        return None
    depth = structural_depth(data)
    if depth > MAX_MANIFEST_DEPTH:
        add_finding(findings, category="dependency", severity="medium", path=rel, signal=f"{label} nested depth budget exceeded", snippet=f"depth {depth}")
    return data


def file_magic(path: Path) -> str | None:
    try:
        with path.open("rb") as f:
            sample = f.read(16)
    except OSError:
        return None
    if sample.startswith(b"MZ"):
        return "PE executable"
    if sample.startswith(b"\x7fELF"):
        return "ELF executable"
    if sample[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        return "Mach-O or Java/class surface"
    if sample.startswith(b"PK\x03\x04"):
        return "ZIP/JAR archive"
    if sample.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    if sample.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z archive"
    if sample.startswith(b"Rar!\x1a\x07"):
        return "RAR archive"
    if sample.startswith(b"%PDF-"):
        return "PDF document"
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if sample.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if sample.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image"
    if sample.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if sample.startswith(b"\x80\x04") or sample.startswith(b"\x80\x05"):
        return "pickle/model surface"
    return None


def parse_dependencies(root: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    deps: list[dict[str, Any]] = []
    manifests: list[str] = []
    install_hooks: list[dict[str, Any]] = []
    dependency_overflow_reported = False

    def add_dep(dependency_name: str, version_hint: str, ecosystem: str, source: str) -> None:
        nonlocal dependency_overflow_reported
        if len(deps) >= MAX_DEPENDENCY_TOKENS:
            if not dependency_overflow_reported:
                add_finding(
                    findings,
                    category="dependency",
                    severity="low",
                    path=source,
                    signal="dependency token limit hit during static extraction",
                    snippet="manifest has many dependencies",
                )
                dependency_overflow_reported = True
            return
        cleaned = dependency_name.strip()
        if not cleaned:
            return
        deps.append({
            "ecosystem": ecosystem,
            "name": cleaned,
            "version": (version_hint or "unspecified").strip()[:160],
            "direct": True,
            "source": source,
        })

    def parse_lockfile(lock_path: Path) -> list[tuple[str, str]]:
        items: list[tuple[str, str]] = []
        rel = lock_path.relative_to(root).as_posix()

        def extract_package_ref(raw: str) -> str | None:
            token = raw.strip().rstrip(":").split(",", 1)[0].strip().strip("\"'")
            token = token.lstrip("/")
            if "@" not in token:
                return None
            name, _version = token.rsplit("@", 1)
            return name or None

        try:
            if lock_path.name == "package-lock.json":
                lock_data = parse_json_object_file(lock_path, root, findings, label="lockfile")
                if lock_data is None:
                    return items
                lock_deps = lock_data.get("dependencies") or {}
                if not isinstance(lock_deps, dict):
                    add_finding(findings, category="dependency", severity="medium", path=rel, signal="lockfile dependencies section type requires review", snippet=type(lock_deps).__name__)
                    return items
                for name, meta in lock_deps.items():
                    version = meta.get("version", "") if isinstance(meta, dict) else ""
                    items.append((str(name), str(version)))
            elif lock_path.name == "yarn.lock":
                text = read_bounded_text(lock_path, rel, findings, label="lockfile")
                if text is None:
                    return items
                for line in text.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or not stripped.endswith(":"):
                        continue
                    if "@" in stripped:
                        name = extract_package_ref(stripped)
                        if name:
                            items.append((name, "lockfile"))
            elif lock_path.name == "pnpm-lock.yaml":
                text = read_bounded_text(lock_path, rel, findings, label="lockfile")
                if text is None:
                    return items
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.endswith(":") and "/" in stripped:
                        name = extract_package_ref(stripped)
                        if name:
                            items.append((name, "lockfile"))
        except Exception as exc:
            add_finding(findings, category="dependency", severity="low", path=rel, signal="lockfile parse failed", snippet=str(exc))
        return items

    for package_json in root.rglob("package.json"):
        check_scan_deadline("dependency manifest scan")
        rel = package_json.relative_to(root).as_posix()
        manifests.append(rel)
        data = parse_json_object_file(package_json, root, findings, label="package.json")
        if data is None:
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            section_data = data.get(section) or {}
            if not isinstance(section_data, dict):
                add_finding(findings, category="dependency", severity="medium", path=rel, signal=f"package.json {section} section type requires review", snippet=type(section_data).__name__)
                continue
            for name, version in section_data.items():
                add_dep(name, str(version), "npm", rel)
        scripts = data.get("scripts") or {}
        if scripts and not isinstance(scripts, dict):
            add_finding(findings, category="dependency", severity="medium", path=rel, signal="package.json scripts section type requires review", snippet=type(scripts).__name__)
            scripts = {}
        for script_name, command in scripts.items():
            if script_name.lower() in {"preinstall", "install", "postinstall", "prepare"}:
                hook = {"ecosystem": "npm", "script": script_name, "command": redact_line(str(command)), "source": rel}
                install_hooks.append(hook)
                add_finding(findings, category="install_hook", severity="high", path=rel, signal=f"npm {script_name} hook", snippet=str(command))

    for req in root.rglob("requirements*.txt"):
        check_scan_deadline("dependency manifest scan")
        rel = req.relative_to(root).as_posix()
        manifests.append(rel)
        text = read_bounded_text(req, rel, findings, label="manifest")
        if text is None:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement", "-e", "git+", "http://", "https://")):
                add_finding(findings, category="dependency", severity="medium", path=rel, signal="complex Python dependency", snippet=line)
                add_dep(line, "complex", "python", rel)
                continue
            name = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
            add_dep(name, line[len(name):], "python", rel)

    for pyproject in root.rglob("pyproject.toml"):
        check_scan_deadline("dependency manifest scan")
        rel = pyproject.relative_to(root).as_posix()
        manifests.append(rel)
        try:
            text = read_bounded_text(pyproject, rel, findings, label="manifest")
            if text is None:
                continue
            data = tomllib.loads(text)
        except Exception as exc:
            add_finding(findings, category="dependency", severity="low", path=rel, signal="pyproject parse failed", snippet=str(exc))
            continue
        project = data.get("project", {})
        if not isinstance(project, dict):
            add_finding(findings, category="dependency", severity="medium", path=rel, signal="pyproject project section type requires review", snippet=type(project).__name__)
            continue
        dep_items = project.get("dependencies", []) or []
        if not isinstance(dep_items, list):
            add_finding(findings, category="dependency", severity="medium", path=rel, signal="pyproject dependencies section type requires review", snippet=type(dep_items).__name__)
            continue
        for item in dep_items:
            name = re.split(r"[<>=!~;\[]", str(item), maxsplit=1)[0].strip()
            add_dep(name, str(item)[len(name):], "python", rel)

    for manifest_name in ["pom.xml", "build.gradle", "build.gradle.kts", "gradle-wrapper.properties", "go.mod"]:
        for manifest in root.rglob(manifest_name):
            check_scan_deadline("dependency manifest scan")
            rel = manifest.relative_to(root).as_posix()
            manifests.append(rel)
            text = read_bounded_text(manifest, rel, findings, label="manifest")
            if text is None:
                continue
            if manifest_name == "pom.xml":
                for m in POM_DEPENDENCY_RE.finditer(text):
                    add_dep(f"{m.group('group')}:{m.group('artifact')}", "manifest", "java", rel)
            elif manifest_name == "gradle-wrapper.properties":
                continue
            else:
                for line in text.splitlines():
                    if GRADLE_DEPENDENCY_RE.search(line):
                        m = re.search(r"['\"](?P<gav>[^'\"]+)['\"]", line)
                        if m:
                            gav = m.group("gav")
                            if gav.count(":") >= 2:
                                add_dep(gav.rsplit(":", 1)[0], "manifest", "java", rel)

    lockfiles: list[str] = []
    for p in root.rglob("*"):
        check_scan_deadline("lockfile scan")
        if p.is_file() and p.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum"}:
            rel = p.relative_to(root).as_posix()
            lockfiles.append(rel)
            for name, version in parse_lockfile(p):
                add_dep(name, version, "npm" if p.suffix in {".json", ".lock"} else "general", rel)

    return {
        "manifest_files": sorted(set(manifests)),
        "lockfiles": sorted(set(lockfiles)),
        "direct_count": len(deps),
        "dependencies": deps[:MAX_DEPENDENCY_TOKENS],
        "install_hooks": install_hooks,
    }


def infer_metadata(root: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {"repo_identity": "Unknown local ZIP", "source_url": None, "license": None, "readme_title": None, "provenance_signals": []}
    git_config = root / ".git" / "config"
    if not git_config.exists():
        for match in root.rglob(".git/config"):
            check_scan_deadline("metadata scan")
            git_config = match
            break
    if git_config.exists():
        text = git_config.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"url\s*=\s*(.+)", text)
        if m:
            url = re.sub(r"https://[^/@]+:[^/@]+@", "https://", m.group(1).strip())
            metadata["source_url"] = url
            metadata["repo_identity"] = url.replace("https://github.com/", "").replace(".git", "")
            metadata["provenance_signals"].append("git remote detected")
    for package_json in root.rglob("package.json"):
        check_scan_deadline("metadata scan")
        try:
            data = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("repository") and not metadata["source_url"]:
            repo = data["repository"]
            if isinstance(repo, dict):
                repo = repo.get("url")
            metadata["source_url"] = str(repo)
            metadata["repo_identity"] = str(repo).replace("git+", "").replace("https://github.com/", "").replace(".git", "")
        if data.get("author"):
            metadata["author"] = data.get("author")
        break
    for license_file in root.rglob("LICENSE*"):
        check_scan_deadline("metadata scan")
        metadata["license"] = license_file.name
        metadata["provenance_signals"].append("license file detected")
        break
    for readme in root.rglob("README*.*"):
        check_scan_deadline("metadata scan")
        for line in readme.read_text(encoding="utf-8", errors="replace").splitlines():
            cleaned = line.strip().lstrip("#").strip()
            if cleaned:
                metadata["readme_title"] = cleaned[:120]
                break
        break
    return metadata


def build_governance_surface(root: Path) -> dict[str, Any]:
    surface = empty_governance_surface()
    counts = surface["counts"]
    approval_docs = surface["approval_docs"]
    workflow_signals = surface["workflow_signals"]
    maintenance_signals = surface["maintenance_signals"]

    docs_suffixes = {".md", ".txt", ".rst", ".adoc"}
    approval_markers = ("approval", "policy", "guardrail", "governance", "review")

    def add_signal(bucket: list[dict[str, Any]], *, path: str, signal: str) -> None:
        entry = {"path": path, "signal": signal}
        if entry not in bucket and len(bucket) < MAX_PUBLIC_DETAIL_ITEMS:
            bucket.append(entry)

    def workflow_name(path: Path, text: str) -> str:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("name:"):
                return stripped.split(":", 1)[1].strip() or path.stem.replace("-", " ")
        return path.stem.replace("-", " ")

    for path in root.rglob("*"):
        check_scan_deadline("governance scan")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        rel_lower = rel.lower()
        name_lower = path.name.lower()

        if path.suffix.lower() in docs_suffixes and any(marker in name_lower for marker in approval_markers):
            counts["approval_docs"] += 1
            add_signal(approval_docs, path=rel, signal="approval/policy doc")

        if name_lower.startswith("security"):
            counts["security_policy_files"] += 1
            add_signal(maintenance_signals, path=rel, signal="security policy")

        if name_lower.startswith("contributing"):
            counts["contributing_guides"] += 1
            add_signal(maintenance_signals, path=rel, signal="contributing guide")

        if name_lower.startswith("changelog") or name_lower in {"releases.md", "release-notes.md"}:
            counts["changelog_files"] += 1
            add_signal(maintenance_signals, path=rel, signal="changelog / release notes")

        if name_lower == "codeowners" or rel_lower.endswith("/codeowners"):
            counts["codeowners_files"] += 1
            add_signal(maintenance_signals, path=rel, signal="codeowners")

        if "/issue_template/" in f"/{rel_lower}":
            counts["issue_templates"] += 1
            add_signal(maintenance_signals, path=rel, signal="issue template")

        if "/.github/workflows/" in f"/{rel_lower}":
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            name = workflow_name(path, text)
            workflow_blob = f"{rel_lower}\n{text.lower()}"
            if any(token in workflow_blob for token in ("release", "publish", "deploy")):
                counts["release_workflows"] += 1
                add_signal(workflow_signals, path=rel, signal=name or "release workflow")
            if any(token in workflow_blob for token in ("docs", "doc", "site", "preview")):
                counts["docs_workflows"] += 1
                add_signal(workflow_signals, path=rel, signal=name or "docs workflow")

    return surface


def build_security_tool_surface(root: Path | None) -> dict[str, Any]:
    """Extract static security-tool/review-surface signals from scanner/integration repos.

    Batch B taught Repo Brief a useful distinction: a repo can describe powerful scanners,
    CI actions, API discovery, or MCP exposure checks without MAYA being allowed to run any
    of them. This surface captures those patterns as review metadata only.
    """
    surface = empty_security_tool_surface()
    if not root or not root.exists():
        return surface

    counts = surface["counts"]
    signals = surface["signals"]

    def add_signal(rule: dict[str, Any], *, path: str, line: int | None = None, snippet: str = "") -> None:
        rule_id = str(rule["id"])
        counts[rule_id] = int(counts.get(rule_id, 0)) + 1
        if len(signals) >= 36:
            return
        entry = {
            "id": rule_id,
            "label": rule.get("label", rule_id),
            "path": path,
            "line": line,
            "snippet": redact_line(snippet) if snippet else "",
            "recommended_action": rule.get("recommended_action", "Review before promotion."),
        }
        if entry not in signals:
            signals.append(entry)

    def ci_security_workflow_hit(rel_lower: str, text_lower: str) -> bool:
        if "/.github/workflows/" not in f"/{rel_lower}":
            return False
        return any(token in text_lower for token in ("snyk", "codeql", "semgrep", "trivy", "gitleaks", "dependency-review", "security"))

    for path in root.rglob("*"):
        check_scan_deadline("security tool surface scan")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        rel_lower = rel.lower()
        suffix = path.suffix.lower()
        if suffix in BENIGN_ASSET_EXTENSIONS or suffix in BINARY_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_TEXT_SCAN_BYTES or not is_probably_text(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text_lower = text.lower()
        path_blob = f"{rel_lower}\n{text_lower}"
        for rule in COMPILED_SECURITY_TOOL_SURFACE_RULES:
            if rule["id"] == "ci_security_workflows":
                matched = ci_security_workflow_hit(rel_lower, text_lower)
            else:
                matched = any(pattern.search(path_blob) for pattern in rule["compiled"])
            if not matched:
                continue
            sample_line = None
            sample_text = ""
            for idx, line in enumerate(text.splitlines(), start=1):
                if idx % 200 == 0:
                    check_scan_deadline("security tool text scan")
                haystack = f"{rel_lower}\n{line.lower()}"
                if any(pattern.search(haystack) for pattern in rule["compiled"]):
                    sample_line = idx
                    sample_text = line
                    break
            add_signal(rule, path=rel, line=sample_line, snippet=sample_text)

    manual_scope_required = bool(counts.get("live_target_scan") or counts.get("mcp_agent_exposure_scan") or counts.get("api_graphql_surface"))
    detected = sum(int(value) for value in counts.values())
    surface["posture"] = "manual_scope_required" if manual_scope_required else "review_before_promotion" if detected else "no_security_tool_surface_detected"
    surface["human_scope_required"] = manual_scope_required
    if manual_scope_required:
        surface["recommended_review_actions"] = [
            "Require explicit target scope before using any API, GraphQL, MCP, A2A, LLM, recon, or port-scan behavior.",
            "Use the repo as static pattern/reference unless a human approves the exact scan target and allowed network boundary.",
            "Promote safe patterns into MAYA-owned tests/reports rather than importing external scanner execution paths.",
        ]
    return surface


def scan_files(root: Path, inventory: dict[str, Any], deps: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = FindingList()

    for hook in deps.get("install_hooks", []):
        check_scan_deadline("finding scan")
        add_finding(findings, category="install_hook", severity="high", path=hook["source"], signal=f"npm {hook['script']} hook", snippet=hook["command"])

    for path in root.rglob("*"):
        check_scan_deadline("finding scan")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        magic = file_magic(path)
        benign_magic = {
            ".png": "PNG image",
            ".jpg": "JPEG image",
            ".jpeg": "JPEG image",
            ".gif": "GIF image",
        }.get(suffix)
        if magic and benign_magic and magic != benign_magic:
            add_finding(findings, category="binary", severity="medium", path=rel, signal=f"extension/magic mismatch ({suffix} vs {magic})")
            continue
        if suffix in BENIGN_ASSET_EXTENSIONS and (not magic or magic == benign_magic):
            continue
        if suffix in ARCHIVE_EXTENSIONS or (magic and any(token in magic for token in ("archive", "ZIP/JAR"))):
            add_finding(findings, category="binary", severity="medium", path=rel, signal=f"nested archive or packaged binary surface detected ({magic or suffix})")
            continue
        if suffix in MODEL_REVIEW_EXTENSIONS or (magic and "pickle" in magic):
            add_finding(findings, category="binary", severity="medium", path=rel, signal=f"pickle/model review surface detected ({suffix or magic})")
            continue
        if magic and any(token in magic for token in ("PE executable", "ELF executable", "Mach-O", "Java/class", "SQLite", "PDF")):
            add_finding(findings, category="binary", severity="medium", path=rel, signal=f"binary magic surface detected ({magic})")
            continue
        if suffix in BINARY_EXTENSIONS or not is_probably_text(path):
            severity = "high" if suffix in {".exe", ".dll", ".so", ".dylib", ".msi", ".deb", ".rpm", ".app"} else "medium"
            add_finding(findings, category="binary", severity=severity, path=rel, signal=f"binary/executable surface detected ({suffix or 'no extension'})")
            continue
        if size > MAX_TEXT_SCAN_BYTES:
            add_finding(findings, category="obfuscation", severity="medium", path=rel, signal="large text file skipped", snippet=f"{size} bytes")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            add_finding(findings, category="filesystem", severity="medium", path=rel, signal="file unreadable on host", snippet=str(exc))
            continue
        lower_name = path.name.lower()
        if lower_name == ".env" or ".env" in rel.lower() or lower_name in {"id_rsa", "id_dsa"} or suffix == ".pem":
            add_finding(findings, category="credential", severity="high", path=rel, signal="credential-shaped file present", snippet="contents redacted")
        for idx, line in enumerate(text.splitlines(), start=1):
            if idx % 200 == 0:
                check_scan_deadline("text finding scan")
            if SECRET_TOKEN_RE.search(line) or SECRET_ASSIGNMENT_RE.search(line):
                add_finding(findings, category="credential", severity="high", path=rel, line=idx, signal="secret-shaped value", snippet=line)
            if BASE64_BLOB_RE.search(line):
                add_finding(findings, category="obfuscation", severity="medium", path=rel, line=idx, signal="large encoded blob", snippet="encoded blob redacted")
            for signal, pattern in PROCESS_PATTERNS:
                if pattern.search(line):
                    sev = "high" if signal in {"pipe-to-shell", "reverse shell"} else "medium"
                    add_finding(findings, category="process", severity=sev, path=rel, line=idx, signal=signal, snippet=line)
            for signal, pattern in NETWORK_PATTERNS:
                if pattern.search(line):
                    severity = hardcoded_url_severity(line, rel) if signal == "hardcoded URL" else "medium"
                    if severity:
                        add_finding(findings, category="network", severity=severity, path=rel, line=idx, signal=signal, snippet=line)
            for signal, pattern in FILESYSTEM_PATTERNS:
                if pattern.search(line):
                    add_finding(findings, category="filesystem", severity="high", path=rel, line=idx, signal=signal, snippet=line)
            for signal, pattern in TELEMETRY_PATTERNS:
                if pattern.search(line):
                    add_finding(findings, category="intrusiveness", severity="medium", path=rel, line=idx, signal=signal, snippet=line)
            for signal, severity in classify_phishing_signals(line, rel):
                add_finding(findings, category="phishing", severity=severity, path=rel, line=idx, signal=signal, snippet=line)
    return findings


def severity_points(findings: list[dict[str, Any]], categories: set[str] | None = None) -> int:
    weights = {"critical": 45, "high": 25, "medium": 6, "low": 1, "info": 0}
    total = 0
    for f in findings:
        if categories and f["category"] not in categories:
            continue
        total += weights.get(f.get("severity", "info"), 1)
    return total


def clamp(n: float, low: int = 0, high: int = 100) -> int:
    return int(max(low, min(high, round(n))))


def make_axis(
    value: int,
    polarity: str,
    confidence: str,
    interpretation: str,
    *,
    color: str | None = None,
    status_label: str | None = None,
    reward_note: str | None = None,
    review_options: list[str] | None = None,
) -> dict[str, Any]:
    if color is None:
        if polarity == "HIGH_BAD":
            color = "green" if value <= 20 else "blue" if value <= 49 else "red"
        elif polarity == "HIGH_GOOD":
            color = "green" if value >= 70 else "blue" if value >= 20 else "red"
        else:  # LOW_BAD, where low means weakness/risk.
            color = "green" if value >= 80 else "blue" if value >= 55 else "red"
    risk_level = {"green": "low", "blue": "medium", "amber": "medium", "orange": "medium", "red": "high"}[color]
    status_label = public_state(status_label or {"green": PUBLIC_NO_SIGNAL, "blue": PUBLIC_REVIEW, "amber": PUBLIC_REVIEW, "orange": PUBLIC_REVIEW, "red": PUBLIC_RISK}[color])
    axis = {
        "value": clamp(value),
        "polarity": polarity,
        "confidence": confidence,
        "color": color,
        "risk_level": risk_level,
        "status_label": status_label,
        "interpretation": interpretation,
    }
    if reward_note:
        axis["reward_note"] = reward_note
    if review_options:
        axis["review_options"] = review_options
    return axis


def is_reference_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    parts = lower.split("/")
    return (
        any(part in {"docs", "doc", "examples", "example", "samples", "sample", "test", "tests", "fixtures", "fixture", "demo", "demos"} for part in parts)
        or lower.endswith((".example", ".sample", ".template"))
        or ".env.example" in lower
        or "readme" in lower
    )


def is_ci_or_workflow_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    return "/.github/workflows/" in f"/{lower}" or "/.circleci/" in f"/{lower}" or "/ci/" in f"/{lower}"


def is_true_danger_finding(finding: dict[str, Any]) -> bool:
    category = finding.get("category")
    signal = str(finding.get("signal", "")).lower()
    severity = finding.get("severity")
    path = str(finding.get("path", ""))
    if category == "archive_safety":
        return True
    if category == "install_hook":
        return True
    if category == "credential":
        return not is_reference_path(path)
    if category == "binary":
        return severity in {"critical", "high"}
    if category == "filesystem":
        return ("dangerous deletion" in signal or "persistence command" in signal) and not is_reference_path(path) and not is_ci_or_workflow_path(path)
    if category == "process":
        return ("reverse shell" in signal or "pipe-to-shell" in signal) and not is_reference_path(path) and not is_ci_or_workflow_path(path)
    if category == "phishing":
        return severity in {"critical", "high"} and not is_reference_path(path) and not is_ci_or_workflow_path(path)
    return False


def actionable_findings(findings: list[dict[str, Any]], categories: set[str]) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("category") in categories and is_true_danger_finding(f)]


def reference_findings(findings: list[dict[str, Any]], categories: set[str]) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("category") in categories and is_reference_path(str(f.get("path", "")))]


def axis_from_pressure(value: int, *, has_review_signal: bool, red_at: int = 50) -> tuple[str, str]:
    if value >= red_at:
        return "red", PUBLIC_RISK
    if has_review_signal or value > 0:
        return "blue", PUBLIC_REVIEW
    return "green", PUBLIC_NO_SIGNAL


def build_ai_component_bom(root: Path, inventory: dict[str, Any], deps: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    """Static AI/application BOM inspired by Batch 002 agent-bom/aibom/supply-chain repos."""
    components: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_paths: set[str] = set()
    for path in root.rglob("*"):
        check_scan_deadline("AI component BOM scan")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        for component_type, pattern in AI_COMPONENT_RULES:
            if pattern.search(rel):
                if rel in seen_paths and component_type != "security_scanner":
                    continue
                counts[component_type] += 1
                seen_paths.add(rel)
                components.append({
                    "type": component_type,
                    "path": rel,
                    "reason": component_type.replace("_", " "),
                })
                break
    ecosystems = Counter(dep.get("ecosystem", "unknown") for dep in deps.get("dependencies", []))
    return {
        "version": "maya_ai_component_bom_v0_2",
        "source_patterns": [
            "msaad00/agent-bom SBOM and agent repo inventory",
            "cisco-ai-defense/aibom AI BOM and scan pipeline",
            "artifact-keeper/artifact metadata and retention receipts",
        ],
        "repo_identity": metadata.get("repo_identity"),
        "source_url": metadata.get("source_url"),
        "component_count": len(components),
        "component_type_counts": dict(counts),
        "dependency_ecosystems": dict(ecosystems),
        "dependency_direct_count": deps.get("direct_count", 0),
        "manifest_files": deps.get("manifest_files", []),
        "lockfiles": deps.get("lockfiles", []),
        "artifact": {
            "file_count": inventory.get("file_count", 0),
            "total_mb": inventory.get("total_mb", 0),
            "largest_files": inventory.get("largest_files", [])[:5],
        },
        "components": components[:MAX_PUBLIC_DETAIL_ITEMS],
    }


def empty_ai_component_bom(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "maya_ai_component_bom_v0_2",
        "source_patterns": [
            "msaad00/agent-bom SBOM and agent repo inventory",
            "cisco-ai-defense/aibom AI BOM and scan pipeline",
            "artifact-keeper/artifact metadata and retention receipts",
        ],
        "repo_identity": metadata.get("repo_identity"),
        "source_url": metadata.get("source_url"),
        "component_count": 0,
        "component_type_counts": {},
        "dependency_ecosystems": {},
        "dependency_direct_count": 0,
        "manifest_files": [],
        "lockfiles": [],
        "artifact": {
            "file_count": 0,
            "total_mb": 0,
            "largest_files": [],
        },
        "components": [],
    }


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    for finding in findings:
        key = (finding.get("category", "unknown"), finding.get("signal", "unknown"))
        item = grouped.setdefault(key, {
            "category": key[0],
            "signal": key[1],
            "count": 0,
            "max_severity": finding.get("severity", "info"),
            "sample_paths": [],
        })
        item["count"] += 1
        if severity_rank.get(finding.get("severity", "info"), 1) > severity_rank.get(item["max_severity"], 1):
            item["max_severity"] = finding.get("severity", "info")
        if len(item["sample_paths"]) < 5:
            item["sample_paths"].append(finding.get("path", ""))
    return sorted(grouped.values(), key=lambda item: (-item["count"], item["category"], item["signal"]))[:MAX_PUBLIC_DETAIL_ITEMS]


def build_advisory_triage(
    findings: list[dict[str, Any]],
    finding_groups: list[dict[str, Any]],
    security_routing: dict[str, Any],
    deps: dict[str, Any],
    ai_bom: dict[str, Any],
) -> dict[str, Any]:
    decision = str(security_routing.get("decision") or "standard_static_review")
    urgency = ADVISORY_URGENCY_BY_DECISION.get(decision, "review")
    component_counts = ai_bom.get("component_type_counts", {})
    top_categories = [
        {
            "category": group.get("category", "unknown"),
            "signal": group.get("signal", "signal"),
            "count": group.get("count", 0),
            "max_severity": group.get("max_severity", "info"),
        }
        for group in finding_groups[:5]
    ]

    focus = []
    if component_counts.get("mcp_server", 0):
        focus.append("MCP/tool surface")
    if component_counts.get("agent_instruction", 0):
        focus.append("skill/prompt surface")
    if deps.get("direct_count", 0):
        focus.append("dependency/advisory surface")
    if any(f.get("category") == "credential" for f in findings):
        focus.append("credential-shaped signals")
    if any(f.get("category") == "phishing" for f in findings):
        focus.append("phishing / impersonation signals")
    if not focus:
        focus.append("static repo review")

    owner = "Repo Brief review"
    if decision in {"block_review_before_any_run", "deep_artifact_escalation"}:
        owner = "Manual safety review"
    elif component_counts.get("mcp_server", 0) or component_counts.get("agent_instruction", 0):
        owner = "MAYA policy review"

    actions_by_decision = {
        "block_review_before_any_run": [
            "Do not run, install, or import this repo beyond static review.",
            "Read the artifact receipt and grouped findings before deciding whether the repo deserves a narrower follow-up.",
            "Only continue with a trusted sanitized export or an explicit manual safety-review scope.",
        ],
        "deep_artifact_escalation": [
            "Keep the archive static-only and treat it like a deeper artifact review path, not a casual dependency review.",
            "Use a narrower SBOM or firmware-style follow-up if someone explicitly wants deeper analysis.",
            "Do not let size or binary surface bait MAYA into execution-first behavior.",
        ],
        "advisory_enrichment_review": [
            "Translate the top grouped findings into plain-English owner/action pairs before anyone touches runtime behavior.",
            "Use dependency, credential, and process findings as a remediation queue, not as a dramatic one-number safety score.",
            "Keep the fence static-only until a human chooses a narrower follow-up review path.",
        ],
        "standard_static_review": [
            "Read the grouped findings and remediation plan once before deciding whether the repo deserves any active promotion.",
            "Keep MAYA in read-only mode; do not invent urgency when the scan is mostly documentation and guidance material.",
            "If the repo stays useful after review, capture the pattern in docs, tests, or your own implementation plan instead of copying code blindly.",
        ],
    }

    return {
        "version": "maya_advisory_triage_v0_1",
        "urgency": urgency,
        "owner": owner,
        "primary_focus": focus,
        "top_categories": top_categories,
        "recommended_actions": actions_by_decision.get(decision, actions_by_decision["standard_static_review"]),
        "pattern_sources": [
            "future-architect/vuls advisory prioritization",
            "snyk/snyk-intellij-plugin remediation UX",
            "snyk/agent-scan static advisory framing",
        ],
    }


def build_agentic_surface(
    findings: list[dict[str, Any]],
    ai_bom: dict[str, Any],
    deps: dict[str, Any],
    security_routing: dict[str, Any],
) -> dict[str, Any]:
    component_counts = ai_bom.get("component_type_counts", {})
    counts = {
        "mcp_server": int(component_counts.get("mcp_server", 0)),
        "agent_instruction": int(component_counts.get("agent_instruction", 0)),
        "workflow_automation": int(component_counts.get("workflow_automation", 0)),
        "model_or_prompt_asset": int(component_counts.get("model_or_prompt_asset", 0)),
        "security_scanner": int(component_counts.get("security_scanner", 0)),
    }
    surfaces = []
    for key, label in [
        ("mcp_server", "MCP servers / tool surfaces"),
        ("agent_instruction", "Agent instructions / skill surfaces"),
        ("workflow_automation", "Workflow automation"),
        ("model_or_prompt_asset", "Prompt/model/eval assets"),
        ("security_scanner", "Scanner / audit logic"),
    ]:
        if counts[key]:
            surfaces.append({"surface": key, "label": label, "count": counts[key]})

    finding_categories = Counter(str(f.get("category") or "unknown") for f in findings)
    policy_checks = []
    for key in ["mcp_server", "agent_instruction", "workflow_automation", "model_or_prompt_asset", "security_scanner"]:
        if counts[key]:
            policy_checks.append({"surface": key, "check": AGENTIC_POLICY_GUIDANCE[key]})
    if deps.get("install_hooks"):
        policy_checks.append({"surface": "install_hook", "check": "Treat install hooks as approval-gated execution paths, even when the repo markets itself as a scanner or helper."})
    if finding_categories.get("process") or finding_categories.get("filesystem"):
        policy_checks.append({"surface": "execution_path", "check": "Review process/filesystem behavior for hidden tool execution, persistence, or local data touch before promoting the pattern."})
    if finding_categories.get("network"):
        policy_checks.append({"surface": "network_path", "check": "Confirm what leaves the machine, which endpoints are called, and whether the repo assumes live internet access by default."})

    posture = "reference_only"
    if counts["mcp_server"] or counts["agent_instruction"] or counts["workflow_automation"]:
        posture = "policy_review"
    if security_routing.get("decision") == "block_review_before_any_run":
        posture = "hold"

    owner = "Repo Brief review"
    if posture in {"policy_review", "hold"}:
        owner = "MAYA policy review"
    elif counts["security_scanner"] or counts["model_or_prompt_asset"]:
        owner = "MAYA pattern review"

    return {
        "version": "maya_agentic_surface_v0_1",
        "posture": posture,
        "owner": owner,
        "component_counts": counts,
        "surfaces": surfaces,
        "policy_checks": policy_checks[:8],
        "pattern_sources": [
            "NVIDIA/SkillSpector skill vulnerability taxonomy",
            "HeadyZhang/agent-audit agent SAST framing",
            "cisco-ai-defense/mcp-scanner MCP safety checks",
            "confident-ai/deepteam red-team test taxonomy",
            "gautamvarmadatla/mcpsafetywarden MCP guard posture",
        ],
    }


def empty_action_boundary_review(*, manual_approval_required: bool = False, status: str = "no_instruction_surface_detected") -> dict[str, Any]:
    return {
        "version": "maya_action_boundary_review_v0_1",
        "decision": "manual_review_required" if manual_approval_required else "standard_static_review",
        "manual_approval_required": manual_approval_required,
        "authority_classes": [],
        "recommended_actions": [],
        "instruction_surface_integrity": {
            "status": status,
            "agent_instruction_count": 0,
            "mcp_server_count": 0,
            "workflow_automation_count": 0,
            "approval_doc_count": 0,
            "checks": [],
        },
        "review_gate": {
            "static_gate_before_touch": True,
            "clean_copy_mode": "future_manual_follow_up_only",
            "execution_allowed_by_this_scan": False,
        },
        "pattern_sources": [
            "Rul1an/assay policy-as-code evidence framing",
            "hugoii/llm-agent-audit authority-class review",
            "snapsynapse/guidecheck instruction-surface integrity",
            "PrismorSec/prismor coding-agent safety hook vocabulary",
            "kubouchiyuya/komainu static gate-before-touch pattern",
        ],
    }


def build_action_boundary_review(
    root: Path | None,
    ai_bom: dict[str, Any],
    deps: dict[str, Any],
    findings: list[dict[str, Any]],
    governance_surface: dict[str, Any],
    security_routing: dict[str, Any],
) -> dict[str, Any]:
    """Build action-boundary receipt metadata from static-analysis safety patterns.

    Static-only. This extracts authority-class signals; it never grants execution permission.
    """
    evidence_by_rule: dict[str, list[dict[str, Any]]] = {rule["id"]: [] for rule in COMPILED_ACTION_BOUNDARY_RULES}

    def add_evidence(rule_id: str, *, path: str, line: int | None = None, snippet: str = "") -> None:
        bucket = evidence_by_rule[rule_id]
        entry = {"path": path, "line": line, "snippet": redact_line(snippet) if snippet else ""}
        if entry not in bucket and len(bucket) < 8:
            bucket.append(entry)

    if root and root.exists():
        for path in root.rglob("*"):
            check_scan_deadline("action boundary scan")
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            suffix = path.suffix.lower()
            if suffix in BENIGN_ASSET_EXTENSIONS or suffix in BINARY_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > MAX_TEXT_SCAN_BYTES or not is_probably_text(path):
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            path_blob = rel.lower()
            for idx, line in enumerate(text.splitlines(), start=1):
                if idx % 200 == 0:
                    check_scan_deadline("action boundary text scan")
                haystack = f"{path_blob}\n{line.lower()}"
                for rule in COMPILED_ACTION_BOUNDARY_RULES:
                    if any(pattern.search(haystack) for pattern in rule["compiled"]):
                        add_evidence(rule["id"], path=rel, line=idx, snippet=line)

    for hook in deps.get("install_hooks", []):
        add_evidence("tool_execution", path=hook.get("source", "package.json"), snippet=hook.get("command", "install hook"))
    for finding in findings:
        category = finding.get("category")
        if category == "credential":
            add_evidence("credential_or_secret", path=finding.get("path", ""), line=finding.get("line"), snippet=finding.get("snippet", "credential-shaped signal"))
        elif category in {"process", "install_hook"}:
            add_evidence("tool_execution", path=finding.get("path", ""), line=finding.get("line"), snippet=finding.get("snippet", finding.get("signal", "execution signal")))
        elif category == "filesystem" and is_true_danger_finding(finding):
            add_evidence("destructive_filesystem", path=finding.get("path", ""), line=finding.get("line"), snippet=finding.get("snippet", finding.get("signal", "filesystem signal")))
        elif category == "network" and str(finding.get("signal", "")).lower() in {"webhook", "browser/node network"}:
            add_evidence("external_communication", path=finding.get("path", ""), line=finding.get("line"), snippet=finding.get("snippet", finding.get("signal", "network signal")))

    authority_classes = []
    for rule in COMPILED_ACTION_BOUNDARY_RULES:
        evidence = evidence_by_rule[rule["id"]]
        if evidence:
            authority_classes.append({
                "id": rule["id"],
                "label": rule["label"],
                "evidence_count": len(evidence),
                "sample_evidence": evidence[:4],
                "recommended_action": rule["recommended_action"],
            })

    component_counts = ai_bom.get("component_type_counts", {})
    governance_counts = governance_surface.get("counts", {})
    agent_instruction_count = int(component_counts.get("agent_instruction", 0))
    mcp_server_count = int(component_counts.get("mcp_server", 0))
    workflow_count = int(component_counts.get("workflow_automation", 0))
    approval_doc_count = int(governance_counts.get("approval_docs", 0))
    instruction_checks = []
    if agent_instruction_count:
        instruction_checks.append("Compare agent instruction files against the human-approved setup path before importing behavior.")
    if mcp_server_count:
        instruction_checks.append("Verify MCP/tool descriptions, least-privilege scopes, and server allowlists before enabling tools.")
    if workflow_count:
        instruction_checks.append("Review workflow automations for outbound actions, deployments, or approval bypass.")
    if approval_doc_count:
        instruction_checks.append("Use approval/policy docs as review evidence, not as permission to execute.")
    if authority_classes:
        instruction_checks.append("Preserve an action receipt before any authority-sensitive operation leaves static review.")

    integrity_status = "review_required" if instruction_checks else "no_instruction_surface_detected"
    high_authority_ids = {
        "financial_action", "vendor_bank_change", "access_control", "data_export", "record_modification",
        "external_communication", "deployment_or_release", "destructive_filesystem", "credential_or_secret", "tool_execution",
    }
    manual_required = bool(security_routing.get("human_gate_required")) or any(item["id"] in high_authority_ids for item in authority_classes)
    recommended_actions = [item["recommended_action"] for item in authority_classes[:6]]
    if instruction_checks:
        recommended_actions.append("Keep instruction/tool surfaces in static review until a human approves the exact action boundary.")
    if not recommended_actions:
        recommended_actions.append("No authority-sensitive action language surfaced; continue normal static review before trust.")

    review = empty_action_boundary_review(manual_approval_required=manual_required, status=integrity_status)
    review.update({
        "decision": "manual_review_required" if manual_required else "standard_static_review",
        "manual_approval_required": manual_required,
        "authority_classes": authority_classes,
        "recommended_actions": recommended_actions[:8],
        "instruction_surface_integrity": {
            "status": integrity_status,
            "agent_instruction_count": agent_instruction_count,
            "mcp_server_count": mcp_server_count,
            "workflow_automation_count": workflow_count,
            "approval_doc_count": approval_doc_count,
            "checks": instruction_checks[:8],
        },
        "review_gate": {
            "static_gate_before_touch": True,
            "clean_copy_mode": "future_manual_follow_up_only",
            "execution_allowed_by_this_scan": False,
        },
    })
    return review


def build_public_receipt(result: dict[str, Any]) -> dict[str, Any]:
    receipt = result.get("artifact_receipt", {})
    routing = result.get("security_routing", {})
    triage = result.get("advisory_triage", {})
    boundary = result.get("action_boundary_review", {})
    axes = result.get("axes", {})
    security_tool_surface = result.get("security_tool_surface", {})
    return {
        "version": "maya_repo_brief_public_receipt_v0_1",
        "tool": "MAYA Repo Brief",
        "source_zip": result.get("source_zip"),
        "source_sha256": result.get("source_sha256"),
        "completed_at": result.get("completed_at"),
        "status": result.get("status"),
        "disclaimer": result.get("disclaimer"),
        "static_only": bool(receipt.get("static_only", True)),
        "executed_repo_code": bool(receipt.get("executed_repo_code", False)),
        "installed_dependencies": bool(receipt.get("installed_dependencies", False)),
        "network_calls": bool(receipt.get("network_calls", False)),
        "archive_safety": receipt.get("archive_safety", {}).get("status", "unknown"),
        "review_decision": routing.get("decision", "standard_static_review"),
        "human_gate_required": bool(routing.get("human_gate_required") or boundary.get("manual_approval_required")),
        "review_route": triage.get("owner", "Repo Brief review"),
        "axis_statuses": {name: axis.get("status_label") for name, axis in axes.items()},
        "finding_count": len(result.get("findings", [])),
        "component_count": result.get("ai_bom", {}).get("component_count", 0),
        "action_boundaries": [item.get("label") for item in boundary.get("authority_classes", [])],
        "security_tool_surface": {
            "posture": security_tool_surface.get("posture", "not_available"),
            "human_scope_required": bool(security_tool_surface.get("human_scope_required", False)),
            "counts": security_tool_surface.get("counts", {}),
        },
        "recommended_actions": (boundary.get("recommended_actions", []) + security_tool_surface.get("recommended_review_actions", []) + triage.get("recommended_actions", []))[:8],
        "fence": FENCE,
    }


def build_remediation_plan(findings: list[dict[str, Any]], deps: dict[str, Any], ai_bom: dict[str, Any]) -> list[dict[str, Any]]:
    categories = {finding.get("category") for finding in findings}
    plan: list[dict[str, Any]] = []
    priority = 1
    for category, action in REMEDIATION_BY_CATEGORY.items():
        if category in categories:
            plan.append({"priority": priority, "category": category, "action": action})
            priority += 1
    if deps.get("direct_count", 0) and not deps.get("lockfiles"):
        plan.append({"priority": priority, "category": "dependency", "action": "Add or verify lockfiles before install; missing lockfiles are Review, not automatic Risk."})
        priority += 1
    if ai_bom.get("component_type_counts", {}).get("agent_instruction"):
        plan.append({"priority": priority, "category": "agent_instruction", "action": "Review agent instruction files for prompt-injection, hidden policy changes, and tool-scope claims before importing behavior."})
    return plan


def build_security_routing(
    inventory: dict[str, Any],
    deps: dict[str, Any],
    findings: list[dict[str, Any]],
    axes: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    source_path: str,
) -> dict[str, Any]:
    docs_markers = (
        "readme",
        "docs/",
        "/docs/",
        ".md",
        ".rst",
        ".txt",
        "example/",
        "/example/",
        "examples/",
        "/examples/",
        "sample/",
        "/sample/",
        "samples/",
        "/samples/",
        "demo/",
        "/demo/",
        "test/",
        "/test/",
        "tests/",
        "/tests/",
        "fixture/",
        "/fixture/",
        "fixtures/",
        "/fixtures/",
        "changelog",
        ".gitbook/",
        "openapi",
        "swagger",
        "api-spec",
        "reference/",
        "/reference/",
        "site/",
        "/site/",
    )
    reference_secret_markers = (
        ".env.example",
        ".gitleaksignore",
        "example",
        "sample",
        "template",
        ".github/workflows/",
    )
    quarantine_patterns = (
        re.compile(r"(^|[^a-z])(payload|shellcode|dropper|backdoor|botnet|keylogger|beacon|stager)([^a-z]|$)"),
        re.compile(r"(^|[^a-z])c2([^a-z]|$)"),
        re.compile(r"reverse[-_ ]shell"),
    )
    artifact_markers = ("firmware", "sbom", "artifact", "image", "emba")
    advisory_markers = ("vuls", "snyk", "security_graph", "sentinel", "advisory", "vuln")
    executable_binary_exts = {".exe", ".dll", ".so", ".dylib", ".msi", ".deb", ".rpm", ".app", ".bin", ".elf", ".scr"}
    artifact_binary_exts = {".jar", ".war", ".apk", ".ipa", ".img", ".iso", ".qcow2", ".vmdk"}

    source_path_lower = source_path.lower()
    source_url_lower = str(metadata.get("source_url") or "").lower()
    source_identity_lower = str(metadata.get("repo_identity") or "").lower()
    source_readme_lower = str(metadata.get("readme_title") or "").lower()
    source_blob = " ".join([source_path_lower, source_url_lower, source_identity_lower, source_readme_lower])
    dep_heavy = deps.get("direct_count", 0) >= 4 or bool(deps.get("lockfiles")) or bool(deps.get("manifest_files"))

    def is_docs_like(path: str) -> bool:
        lowered = path.lower()
        return any(marker in lowered for marker in docs_markers)

    def is_reference_secret(path: str) -> bool:
        lowered = path.lower()
        return any(marker in lowered for marker in reference_secret_markers)

    live_findings = [finding for finding in findings if not is_docs_like(str(finding.get("path") or ""))]
    live_counts: dict[str, int] = {}
    live_executable_binaries = 0
    live_artifact_binaries = 0
    live_reference_safe_credentials = 0
    live_actionable_credentials = 0
    offensive_signal_hits = 0

    for finding in live_findings:
        category = str(finding.get("category") or "unknown")
        live_counts[category] = live_counts.get(category, 0) + 1
        path_text = str(finding.get("path") or "")
        lowered_path = path_text.lower()
        signal_blob = " ".join(
            [
                lowered_path,
                str(finding.get("signal") or "").lower(),
                str(finding.get("snippet") or "").lower(),
            ]
        )
        suffix = Path(path_text).suffix.lower()
        if category == "binary":
            if suffix in executable_binary_exts:
                live_executable_binaries += 1
            elif suffix in artifact_binary_exts:
                live_artifact_binaries += 1
        if category == "credential":
            if is_reference_secret(path_text):
                live_reference_safe_credentials += 1
            else:
                live_actionable_credentials += 1
        if any(pattern.search(signal_blob) for pattern in quarantine_patterns):
            offensive_signal_hits += 1

    decision = "standard_static_review"
    recommended_lane = "Stay in MAYA Repo Brief static review, read the grouped findings, and only escalate if a human wants deeper analysis."
    why = [
        "Tier 1 static screening completed without a red-flag execution blocker.",
        "No deeper vulnerability or artifact review path is required before human review.",
    ]
    human_gate_required = False

    curated_quarantine = "04_defensive_quarantine" in source_path_lower
    artifact_family = any(marker in source_blob for marker in artifact_markers)
    advisory_family = dep_heavy or any(marker in source_blob for marker in advisory_markers)
    live_process = live_counts.get("process", 0)
    live_network = live_counts.get("network", 0)
    live_filesystem = live_counts.get("filesystem", 0)
    live_obfuscation = live_counts.get("obfuscation", 0)
    live_phishing = live_counts.get("phishing", 0)
    install_hooks_present = bool(deps.get("install_hooks"))

    large_archive = axes.get("Storage Footprint", {}).get("value", 0) >= 60
    artifact_pressure = live_filesystem >= 20 or live_counts.get("binary", 0) >= 1 or (large_archive and live_process >= 10)

    if curated_quarantine or install_hooks_present or live_executable_binaries or (live_actionable_credentials >= 20 and live_process >= 10 and live_obfuscation >= 3):
        decision = "block_review_before_any_run"
        recommended_lane = "Hold execution, keep the repo static-only, and require manual safety review before any run/install decision."
        why = [
            "Tier 1 screening found either a quarantined source context, install hooks, offensive payload-like signals, executable binaries, or a credential/process mix that should never be normalized into casual execution.",
            "This belongs in a human review queue before MAYA touches the repo beyond static inspection.",
        ]
        human_gate_required = True
    elif live_phishing >= 2 and (live_process or live_network or live_actionable_credentials):
        decision = "block_review_before_any_run"
        recommended_lane = "Hold execution. Multiple phishing/impersonation signals co-occur with execution or credential surface; treat the repo as likely malicious bait until manually cleared."
        why = [
            "Multiple shortlink/lookalike/harvest/exfil signals appear alongside process, network, or credential surface. This is the signature of a phishing repo, not a security reference.",
            "Keep static-only, expand every redacted URL, and require a human safety verdict before any execution or install decision.",
        ]
        human_gate_required = True
    elif live_phishing >= 1:
        decision = "advisory_enrichment_review"
        recommended_lane = "Keep the repo static and enrich phishing findings with destination checks and credential-harvest context before any trust decision."
        why = [
            "The repo contains phishing/impersonation signals (shortlink, lookalike host, harvest language, or exfil endpoint). Verify every destination before promotion.",
            "Documentation references stay advisory; code/HTML signals carry the weight.",
        ]
    elif live_artifact_binaries or (artifact_family and artifact_pressure):
        decision = "deep_artifact_escalation"
        recommended_lane = "Keep it static-only and escalate to deeper artifact/SBOM review before any execution or install decision."
        why = [
            "Archive shape looks like a deep artifact / firmware / SBOM lane rather than a simple dependency advisory pass.",
            "Use an EMBA-style deep artifact lane only as read-only analysis, never as blind execution.",
        ]
        human_gate_required = True
    elif advisory_family or live_network >= 80 or live_process >= 25 or live_actionable_credentials >= 5 or live_reference_safe_credentials >= 5 or large_archive:
        decision = "advisory_enrichment_review"
        recommended_lane = "Keep the repo static, enrich findings with dependency/advisory context, and turn the result into plain-English remediation guidance."
        why = [
            "The repo looks like a reference-safe security or dependency surface that benefits more from context-rich advisory review than from a blunt hard block.",
            "Use Vuls/Snyk-style enrichment wording so the next human decision is obvious while preserving the no-run fence.",
        ]

    return {
        "version": "maya_security_routing_v0_2",
        "tier1_screen": "deterministic_static_filter",
        "decision": decision,
        "recommended_lane": recommended_lane,
        "human_gate_required": human_gate_required,
        "why": why,
        "routing_context": {
            "live_counts": live_counts,
            "live_actionable_credentials": live_actionable_credentials,
            "live_reference_safe_credentials": live_reference_safe_credentials,
            "live_executable_binaries": live_executable_binaries,
            "live_artifact_binaries": live_artifact_binaries,
            "offensive_signal_hits": offensive_signal_hits,
            "live_phishing": live_phishing,
            "curated_quarantine": curated_quarantine,
            "install_hooks_present": install_hooks_present,
        },
        "pattern_sources": [
            "Binhchuoizzz/AI_Security_Graph two-tier escalation",
            "future-architect/vuls advisory enrichment",
            "e-m-b-a/emba deep artifact boundary",
            "snyk/snyk-intellij-plugin remediation clarity",
        ],
    }


def build_artifact_receipt(
    zip_path: Path,
    sha: str,
    inventory: dict[str, Any],
    metadata: dict[str, Any],
    ai_bom: dict[str, Any],
    deps: dict[str, Any],
    *,
    archive_safety_status: str = "passed",
    blocked_reason: str | None = None,
    extraction_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": "maya_repo_artifact_receipt_v0_2",
        "source_patterns": [
            "artifact-keeper/artifact retention metadata",
            "coproduct-opensource/nucleus verifiable receipt framing",
            "msaad00/agent-bom inventory framing",
            "cisco-ai-defense/aibom AI BOM inventory framing",
        ],
        "input_name": zip_path.name,
        "sha256": sha,
        "repo_identity": metadata.get("repo_identity"),
        "source_url": metadata.get("source_url"),
        "file_count": inventory.get("file_count", 0),
        "total_mb": inventory.get("total_mb", 0),
        "ai_component_count": ai_bom.get("component_count", 0),
        "component_type_counts": ai_bom.get("component_type_counts", {}),
        "manifest_file_count": len(deps.get("manifest_files", [])),
        "lockfile_count": len(deps.get("lockfiles", [])),
        "install_hook_count": len(deps.get("install_hooks", [])),
        "archive_safety": {
            "status": archive_safety_status,
            "blocked_reason": blocked_reason,
            "extraction_metrics": extraction_metrics or {
                "file_count": 0,
                "total_extracted_bytes": 0,
                "files": [],
                "total_declared_uncompressed_bytes": 0,
                "total_declared_compressed_bytes": 0,
                "max_compression_ratio": 0,
            },
        },
        "static_only": True,
        "executed_repo_code": False,
        "installed_dependencies": False,
        "network_calls": False,
    }


def mark_incomplete_axes(axes: dict[str, dict[str, Any]], reason: str) -> dict[str, dict[str, Any]]:
    """Prevent uninspected dimensions from presenting as a green/no-signal result."""
    for axis in axes.values():
        if axis.get("status_label") != PUBLIC_RISK:
            axis["status_label"] = PUBLIC_REVIEW
            axis["color"] = "blue"
        axis["confidence"] = "low"
        axis["interpretation"] = f"{reason} This dimension was not fully evaluated and requires review before trust."
    return axes


def build_blocked_scan_result(zip_path: Path, sha: str, started: str, error: ZipSafetyError) -> dict[str, Any]:
    metadata = {
        "repo_identity": infer_identity_from_zip(zip_path),
        "source_url": None,
        "license": None,
        "readme_title": None,
        "provenance_signals": ["zip intake blocked during guarded intake before static analysis"],
    }
    inventory = empty_inventory()
    deps = empty_dependencies()
    governance_surface = empty_governance_surface()
    security_tool_surface = empty_security_tool_surface()
    ai_bom = empty_ai_component_bom(metadata)
    findings = [{
        "category": "archive_safety",
        "severity": "high",
        "path": zip_path.name,
        "line": None,
        "signal": "zip_policy_block",
        "snippet": redact_line(str(error)),
    }]
    axes = mark_incomplete_axes(
        score_axes(inventory, deps, findings, metadata, governance_surface),
        "ZIP intake stopped during guarded intake before static analysis.",
    )
    finding_groups = group_findings(findings)
    remediation_plan = build_remediation_plan(findings, deps, ai_bom)
    security_routing = {
        "version": "maya_security_routing_v0_2",
        "tier1_screen": "zip_policy_guard",
        "decision": "block_review_before_any_run",
        "recommended_lane": "Keep the archive static-only, preserve the blocked receipt, and only continue if a human provides a trusted sanitized export.",
        "human_gate_required": True,
        "why": [
            f"ZIP intake was blocked during guarded intake before static analysis: {error}",
            "The no-run fence worked as intended; MAYA preserved the archive as reference instead of weakening extraction safety.",
        ],
        "routing_context": {
            "zip_policy_error": str(error),
            "curated_quarantine": False,
            "install_hooks_present": False,
        },
        "pattern_sources": [
            "msaad00/agent-bom symlink-safe intake lesson",
            "snyk/cli symlink-safe intake lesson",
            "artifact-keeper blocked artifact receipt framing",
        ],
    }
    advisory_triage = build_advisory_triage(findings, finding_groups, security_routing, deps, ai_bom)
    agentic_surface = build_agentic_surface(findings, ai_bom, deps, security_routing)
    action_boundary_review = empty_action_boundary_review(manual_approval_required=True, status="blocked_before_extract")
    action_boundary_review["recommended_actions"] = [
        "Keep the archive static-only and only continue from a trusted sanitized export.",
        "Preserve the blocked receipt as proof the no-run fence worked.",
    ]
    artifact_receipt = build_artifact_receipt(
        zip_path,
        sha,
        inventory,
        metadata,
        ai_bom,
        deps,
        archive_safety_status="blocked_before_extract",
        blocked_reason=str(error),
    )
    result = {
        "tool": "MAYA Repo Brief",
        "version": "0.2.0",
        "fence": FENCE,
        "disclaimer": DISCLAIMER,
        "started_at": started,
        "completed_at": now_iso(),
        "source_zip": zip_path.name,
        "source_sha256": sha,
        "status": PUBLIC_BLOCKED,
        "summary": {
            "headline": "MAYA blocked unsafe ZIP intake during guarded intake and preserved a static receipt before static analysis could trust repo contents.",
            "next_step": security_routing["recommended_lane"],
            "not_checked": [
                "No extraction beyond policy guard",
                "No runtime sandboxing",
                "No package installation",
                "No cloud malware database",
                "No guarantee of safety",
            ],
        },
        "metadata": metadata,
        "inventory": inventory,
        "dependencies": deps,
        "governance_surface": governance_surface,
        "security_tool_surface": security_tool_surface,
        "ai_bom": ai_bom,
        "artifact_receipt": artifact_receipt,
        "finding_groups": finding_groups,
        "remediation_plan": remediation_plan,
        "advisory_triage": advisory_triage,
        "agentic_surface": agentic_surface,
        "action_boundary_review": action_boundary_review,
        "security_routing": security_routing,
        "axes": axes,
        "findings": findings,
    }
    result["public_receipt"] = build_public_receipt(result)
    return result


def build_deadline_scan_result(zip_path: Path, sha: str, started: str, error: ScanDeadlineExceeded) -> dict[str, Any]:
    metadata = {
        "repo_identity": infer_identity_from_zip(zip_path),
        "source_url": None,
        "license": None,
        "readme_title": None,
        "provenance_signals": ["scan stopped at local deadline"],
    }
    inventory = empty_inventory()
    deps = empty_dependencies()
    governance_surface = empty_governance_surface()
    security_tool_surface = empty_security_tool_surface()
    ai_bom = empty_ai_component_bom(metadata)
    findings = FindingList()
    add_finding(
        findings,
        category="scanner_deadline",
        severity="medium",
        path=zip_path.name,
        signal="scan deadline exceeded before inspection completed",
        snippet=str(error),
    )
    axes = mark_incomplete_axes(
        score_axes(inventory, deps, findings, metadata, governance_surface),
        "The scan deadline expired before inspection completed.",
    )
    finding_groups = group_findings(findings)
    security_routing = build_security_routing(inventory, deps, findings, axes, metadata, str(zip_path))
    advisory_triage = build_advisory_triage(findings, finding_groups, security_routing, deps, ai_bom)
    agentic_surface = build_agentic_surface(findings, ai_bom, deps, security_routing)
    action_boundary_review = empty_action_boundary_review(manual_approval_required=True, status="deadline_exceeded_incomplete")
    action_boundary_review["recommended_actions"] = [
        "Treat this receipt as incomplete; rerun with a smaller archive or a longer approved local deadline before trust.",
        "Do not run, install, import, or promote code from this archive based on an incomplete scan.",
    ]
    result = {
        "tool": "MAYA Repo Brief",
        "version": "0.2.0",
        "fence": FENCE,
        "disclaimer": DISCLAIMER,
        "started_at": started,
        "completed_at": now_iso(),
        "source_zip": zip_path.name,
        "source_sha256": sha,
        "status": PUBLIC_BLOCKED,
        "summary": {
            "headline": "MAYA stopped the static scan because the local deadline expired before inspection completed.",
            "next_step": "Rerun with a smaller archive or explicitly approved longer local deadline before trust.",
            "not_checked": [
                "Scan incomplete: deadline expired before all static inspection work completed.",
                "What was not inspected: remaining ZIP members, inventory, manifests, text findings, BOM, governance, and action-boundary surfaces after the deadline point.",
                "No runtime sandboxing",
                "No package installation",
                "No cloud malware database",
                "No transitive dependency audit",
                "No guarantee of safety",
            ],
        },
        "metadata": metadata,
        "inventory": inventory,
        "dependencies": deps,
        "governance_surface": governance_surface,
        "security_tool_surface": security_tool_surface,
        "ai_bom": ai_bom,
        "artifact_receipt": build_artifact_receipt(
            zip_path,
            sha,
            inventory,
            metadata,
            ai_bom,
            deps,
            archive_safety_status="deadline_exceeded_incomplete",
            blocked_reason=str(error),
        ),
        "finding_groups": finding_groups,
        "remediation_plan": build_remediation_plan(findings, deps, ai_bom),
        "advisory_triage": advisory_triage,
        "agentic_surface": agentic_surface,
        "action_boundary_review": action_boundary_review,
        "security_routing": security_routing,
        "axes": axes,
        "findings": list(findings),
    }
    result["public_receipt"] = build_public_receipt(result)
    return result



def score_axes(
    inventory: dict[str, Any],
    deps: dict[str, Any],
    findings: list[dict[str, Any]],
    metadata: dict[str, Any],
    governance_surface: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    governance_surface = governance_surface or empty_governance_surface()
    governance_counts = governance_surface.get("counts", {})

    true_danger_categories = {"credential", "binary", "install_hook", "filesystem", "process", "archive_safety", "phishing"}
    advisory_categories = {"network", "dependency", "intrusiveness", "obfuscation"}
    true_danger = actionable_findings(findings, true_danger_categories)
    reference_danger = reference_findings(findings, true_danger_categories)
    advisory = [f for f in findings if f.get("category") in advisory_categories]

    risk = clamp(severity_points(true_danger) + min(20, severity_points(advisory) * 0.20) + min(12, severity_points(reference_danger) * 0.20))
    credential_live = actionable_findings(findings, {"credential"})
    credential_reference = reference_findings(findings, {"credential"})
    credential = clamp(severity_points(credential_live) + min(18, severity_points(credential_reference) * 0.25))
    binary = clamp(severity_points(actionable_findings(findings, {"binary"})) + min(20, severity_points(findings, {"obfuscation"}) * 0.35))
    network = clamp(severity_points(findings, {"network"}))
    intrusiveness = clamp(severity_points(findings, {"intrusiveness"}))
    phishing_live = actionable_findings(findings, {"phishing"})
    phishing_reference = reference_findings(findings, {"phishing"})
    phishing = clamp(severity_points(phishing_live) + min(15, severity_points(phishing_reference) * 0.25))
    filesystem = clamp(severity_points(actionable_findings(findings, {"filesystem", "process", "install_hook"})))

    dependency_count = deps["direct_count"]
    has_lockfile = bool(deps["lockfiles"])
    install_hook_count = len(deps.get("install_hooks", []))
    dep_risk = clamp(min(36, dependency_count * 0.75) + (0 if has_lockfile else 12) + install_hook_count * 25 + severity_points(findings, {"dependency"}) * 0.5)
    size_mb = inventory["total_mb"]
    storage = clamp(5 if size_mb < 1 else 15 if size_mb < 10 else 30 if size_mb < 50 else 45 if size_mb < 200 else 70)

    provenance = 25
    if metadata.get("source_url"):
        provenance += 35
    if metadata.get("license"):
        provenance += 20
    if metadata.get("readme_title"):
        provenance += 15
    if inventory["special"].get("git_metadata"):
        provenance += 15
    maintenance = 70 if inventory["special"].get("readme") and inventory["special"].get("license") else 45 if inventory["special"].get("readme") else 25
    maintenance += min(10, governance_counts.get("security_policy_files", 0) * 10)
    maintenance += min(8, governance_counts.get("contributing_guides", 0) * 8)
    maintenance += min(8, governance_counts.get("changelog_files", 0) * 8)
    maintenance += min(8, governance_counts.get("release_workflows", 0) * 8)
    maintenance += min(6, governance_counts.get("docs_workflows", 0) * 6)
    maintenance += min(4, governance_counts.get("issue_templates", 0) * 4)
    maintenance += min(4, governance_counts.get("codeowners_files", 0) * 4)

    risk_color, risk_label = axis_from_pressure(risk, has_review_signal=bool(true_danger) or severity_points(advisory) > 0 or severity_points(reference_danger) > 0, red_at=50)
    credential_color, credential_label = axis_from_pressure(credential, has_review_signal=bool(credential_reference), red_at=50)
    binary_color, binary_label = axis_from_pressure(binary, has_review_signal=any(f.get("category") in {"binary", "obfuscation"} for f in findings), red_at=50)
    network_color, network_label = ("blue", PUBLIC_REVIEW) if network else ("green", PUBLIC_NO_SIGNAL)
    intrusive_color, intrusive_label = ("blue", PUBLIC_REVIEW) if intrusiveness else ("green", PUBLIC_NO_SIGNAL)
    phishing_color, phishing_label = axis_from_pressure(phishing, has_review_signal=bool(phishing_reference), red_at=50)
    filesystem_color, filesystem_label = axis_from_pressure(filesystem, has_review_signal=any(f.get("category") in {"filesystem", "process", "install_hook"} for f in findings), red_at=50)
    dependency_color = "red" if install_hook_count else "blue" if dependency_count or (deps["manifest_files"] and not has_lockfile) else "green"
    dependency_label = PUBLIC_RISK if install_hook_count else PUBLIC_REVIEW if dependency_color == "blue" else PUBLIC_NO_SIGNAL
    storage_color = "red" if storage >= 85 else "blue" if storage >= 45 else "green"
    storage_label = PUBLIC_RISK if storage_color == "red" else PUBLIC_REVIEW if storage_color == "blue" else PUBLIC_NO_SIGNAL
    install_readiness = clamp(100 - max(risk, credential, binary, filesystem, install_hook_count * 35))
    install_color = "red" if risk_color == "red" or install_hook_count else "blue"
    install_label = "Risk" if install_color == "red" else "Review"
    if risk_color == "green" and dependency_color == "green" and binary_color == "green":
        install_color, install_label = "green", PUBLIC_NO_SIGNAL
    maya_fit = clamp(82 - (risk * 0.22) - (8 if install_hook_count else 0) + (10 if metadata.get("readme_title") else 0) + (8 if deps["manifest_files"] else 0) + min(10, maintenance * 0.08))

    return {
        "Risk Surface": make_axis(
            risk,
            "HIGH_BAD",
            "medium",
            f"MAYA found {len(findings)} static signal(s), but only {len(true_danger)} live danger signal(s). Red is reserved for real secrets, executable/native binaries, install hooks, persistence/destructive filesystem behavior, shell execution, unsafe archives, or clear exfil paths.",
            color=risk_color,
            status_label=risk_label,
            reward_note="Security/tooling repos can still be valuable. I separate scary vocabulary from actual authority and reachability.",
            review_options=["Assess exact findings", "Mark as reference-only", "Request deeper MAYA safety review"],
        ),
        "Install Observations": make_axis(
            install_readiness,
            "HIGH_GOOD",
            "medium",
            "MAYA did not install or run this repo. That is a safety fence, not automatic danger. Review install only if you actually want to use it.",
            color=install_color,
            status_label=install_label,
            review_options=["Keep static-only", "Review install scripts", "Sandbox before any run"],
        ),
        "Intrusiveness": make_axis(intrusiveness, "HIGH_BAD", "medium", "Telemetry, fingerprinting, or behavioral tracking patterns surfaced by text scan. Red requires real collection or tracking behavior, not documentation mentions.", color=intrusive_color, status_label=intrusive_label),
        "Phishing Surface": make_axis(
            phishing,
            "HIGH_BAD",
            "medium",
            "Shortlinks, lookalike domains, brand-impersonation hosts, credential-harvest language, wallet-drainer wording, or exfil endpoints surfaced by text scan. Red requires a live signal in code/HTML, not a documentation reference.",
            color=phishing_color,
            status_label=phishing_label,
            reward_note="MAYA flags impersonation and harvesting signals so you can stay protected while using AI freely. Verify any shortened or lookalike link before trusting the repo.",
            review_options=["Expand redacted URLs", "Confirm destination of each shortlink", "Check wallet-drainer / harvest wording", "Treat exfil endpoints as review-required"],
        ),
        "Dependency Risk": make_axis(
            dep_risk,
            "HIGH_BAD",
            "medium",
            f"{dependency_count} direct dependency signal(s); {'lockfile found — lowers uncertainty' if has_lockfile else 'no lockfile found — review dependency drift'}. Dependency volume is review pressure, not red risk unless install hooks or dangerous execution are present.",
            color=dependency_color,
            status_label=dependency_label,
            reward_note="Dependencies can still mean useful integration surface. I inspect them before rejecting the repo.",
            review_options=["Review dependency ecosystems", "Check lockfile freshness", "Flag install hooks only as Risk"],
        ),
        "Credential Exposure": make_axis(credential, "HIGH_BAD", "medium", "Secret-shaped findings are redacted. Example/template credentials are Review; live credential files or committed keys are Risk.", color=credential_color, status_label=credential_label, review_options=["Open redacted paths", "Confirm example vs live secret", "Quarantine if live credential"]),
        "Binary Surface": make_axis(binary, "HIGH_BAD", "medium", "Executable/native binary files require review. Normal image/media assets and large generated text are not treated as red risk by themselves.", color=binary_color, status_label=binary_label),
        "Network Surface": make_axis(network, "HIGH_BAD", "medium", "External/network strings were surfaced for review. Docs links, fonts, and static references are not red unless paired with execution, telemetry, callbacks, probing, or exfil behavior.", color=network_color, status_label=network_label),
        "Filesystem Surface": make_axis(filesystem, "HIGH_BAD", "medium", "Process, persistence, install hook, or sensitive filesystem patterns surfaced. Red requires actionable file/process authority, not security-topic wording alone.", color=filesystem_color, status_label=filesystem_label),
        "Provenance Signals": make_axis(clamp(provenance), "HIGH_GOOD", "low" if not metadata.get("source_url") else "medium", "Local provenance only unless a source URL/license/README is detected. Better provenance increases trust but does not prove safety."),
        "Storage Footprint": make_axis(storage, "HIGH_BAD", "high", f"Extracted size estimate: {inventory['total_mb']} MB across {inventory['file_count']} files. Large repos are review workload, not red risk unless size comes from binaries, packed payloads, models, or unsafe archives.", color=storage_color, status_label=storage_label, review_options=["Review largest files", "Check binary/model blobs", "Keep as reference if useful"]),
        "Maintenance Health": make_axis(clamp(maintenance), "HIGH_GOOD", "low", "README/license plus governance, release, and contribution signals are reuse signals; they are proxies, not proof of maintenance."),
        "Reuse Indicators": make_axis(
            maya_fit,
            "HIGH_GOOD",
            "low",
            "Usefulness weighs learning/reuse value against real risk. Security repos may still be useful when they stay static-only until reviewed.",
            color="green" if maya_fit >= 70 else "blue" if maya_fit >= 40 else "red",
            status_label="Useful" if maya_fit >= 70 else "Needs context" if maya_fit >= 40 else "Low usefulness",
            reward_note="A reviewed security repo can teach better safety, provenance, and review behavior.",
        ),
    }


def summarize_status(axes: dict[str, dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    """Compute the single authoritative public outcome from all decision axes."""
    axis_states = {public_state(axis.get("status_label")) for axis in axes.values()}
    if PUBLIC_BLOCKED in axis_states:
        return PUBLIC_BLOCKED
    if any(is_true_danger_finding(finding) for finding in findings) or PUBLIC_RISK in axis_states:
        return PUBLIC_RISK
    if findings or PUBLIC_REVIEW in axis_states:
        return PUBLIC_REVIEW
    return PUBLIC_NO_SIGNAL


def scan_zip(zip_path: str | Path, work_root: str | Path | None = None, policy: ZipPolicy | None = None, deadline_seconds: float | None = DEFAULT_SCAN_DEADLINE_SECONDS) -> dict[str, Any]:
    zip_path = Path(zip_path)
    policy = policy or ZipPolicy()
    deadline_token = None
    if _SCAN_DEADLINE.get() is None and deadline_seconds is not None:
        deadline_token = _SCAN_DEADLINE.set(time.monotonic() + deadline_seconds)
    if work_root is None:
        work_root_obj = Path(tempfile.mkdtemp(prefix="maya_lens_"))
        cleanup_parent = True
    else:
        work_root_obj = Path(work_root)
        work_root_obj.mkdir(parents=True, exist_ok=True)
        cleanup_parent = False
    extract_root = work_root_obj / "extracted"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True, exist_ok=True)

    sha = ""
    started = now_iso()
    try:
        sha = file_sha256(zip_path)
        check_scan_deadline("scan start")
        safe_extract(zip_path, extract_root, policy)
        extraction_metrics = getattr(safe_extract, "last_stats", {})
        inventory = inventory_tree(extract_root)
        early_findings: list[dict[str, Any]] = FindingList()
        deps = parse_dependencies(extract_root, early_findings)
        metadata = infer_metadata(extract_root)
        governance_surface = build_governance_surface(extract_root)
        security_tool_surface = build_security_tool_surface(extract_root)
        findings = bound_findings(list(early_findings) + scan_files(extract_root, inventory, deps))
        axes = score_axes(inventory, deps, findings, metadata, governance_surface)
        ai_bom = build_ai_component_bom(extract_root, inventory, deps, metadata)
        finding_groups = group_findings(findings)
        remediation_plan = build_remediation_plan(findings, deps, ai_bom)
        security_routing = build_security_routing(inventory, deps, findings, axes, metadata, str(zip_path))
        advisory_triage = build_advisory_triage(findings, finding_groups, security_routing, deps, ai_bom)
        agentic_surface = build_agentic_surface(findings, ai_bom, deps, security_routing)
        action_boundary_review = build_action_boundary_review(extract_root, ai_bom, deps, findings, governance_surface, security_routing)
        status = summarize_status(axes, findings)
        if action_boundary_review.get("manual_approval_required") or security_tool_surface.get("human_scope_required"):
            status = PUBLIC_REVIEW if status == PUBLIC_NO_SIGNAL else status
        artifact_receipt = build_artifact_receipt(zip_path, sha, inventory, metadata, ai_bom, deps, extraction_metrics=extraction_metrics)
        result = {
            "tool": "MAYA Repo Brief",
            "version": "0.2.0",
            "fence": FENCE,
            "disclaimer": DISCLAIMER,
            "started_at": started,
            "completed_at": now_iso(),
            "source_zip": zip_path.name,
            "source_sha256": sha,
            "status": status,
            "summary": {
                "headline": "MAYA read the repo ZIP, built a static AI/component BOM, and surfaced review signals before anything ran.",
                "next_step": security_routing["recommended_lane"],
                "not_checked": [
                    "No runtime sandboxing",
                    "No package installation",
                    "No cloud malware database",
                    "No transitive dependency audit",
                    "No guarantee of safety",
                ],
            },
            "metadata": metadata,
            "inventory": inventory,
            "dependencies": deps,
            "governance_surface": governance_surface,
            "security_tool_surface": security_tool_surface,
            "ai_bom": ai_bom,
            "artifact_receipt": artifact_receipt,
            "finding_groups": finding_groups,
            "remediation_plan": remediation_plan,
            "advisory_triage": advisory_triage,
            "agentic_surface": agentic_surface,
            "action_boundary_review": action_boundary_review,
            "security_routing": security_routing,
            "axes": axes,
            "findings": findings,
        }
        result["public_receipt"] = build_public_receipt(result)
        return build_public_projection(result)
    except ScanDeadlineExceeded as exc:
        shutil.rmtree(extract_root, ignore_errors=True)
        return build_public_projection(build_deadline_scan_result(zip_path, sha, started, exc))
    except (ZipSafetyError, zipfile.BadZipFile) as exc:
        safety_error = exc if isinstance(exc, ZipSafetyError) else ZipSafetyError(str(exc))
        return build_public_projection(build_blocked_scan_result(zip_path, sha, started, safety_error))
    except RuntimeError as exc:
        if "encrypt" not in str(exc).lower() and "password" not in str(exc).lower():
            raise
        return build_public_projection(build_blocked_scan_result(zip_path, sha, started, ZipSafetyError(str(exc))))
    finally:
        if deadline_token is not None:
            _SCAN_DEADLINE.reset(deadline_token)
        if cleanup_parent:
            shutil.rmtree(work_root_obj, ignore_errors=True)
