from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PUBLIC_RECEIPT_VERSION = "maya_sentinel_public_receipt_v0_2"

PUBLIC_NO_SIGNAL = "No signal detected by this scan"
PUBLIC_REVIEW = "Review"
PUBLIC_RISK = "Risk"
PUBLIC_BLOCKED = "Blocked"
PUBLIC_STATES = {PUBLIC_NO_SIGNAL, PUBLIC_REVIEW, PUBLIC_RISK, PUBLIC_BLOCKED}

PRIVATE_TO_PUBLIC_STATE = {
    "No risk": PUBLIC_NO_SIGNAL,
    "low_static_risk": PUBLIC_NO_SIGNAL,
    "review_recommended": PUBLIC_REVIEW,
    "review_required": PUBLIC_REVIEW,
    "standard_static_review": PUBLIC_REVIEW,
    "advisory_enrichment_review": PUBLIC_REVIEW,
    "deep_artifact_escalation": PUBLIC_REVIEW,
    "block_review_before_any_run": PUBLIC_BLOCKED,
    "blocked_before_extract": PUBLIC_BLOCKED,
    "hold": PUBLIC_RISK,
    "deep_review": PUBLIC_REVIEW,
    "enrich": PUBLIC_REVIEW,
    "review": PUBLIC_REVIEW,
    "Useful": PUBLIC_REVIEW,
    "Needs context": PUBLIC_REVIEW,
    "Low usefulness": PUBLIC_REVIEW,
}

PUBLIC_LANGUAGE_LABELS = {
    "standard_static_review": "Standard static review",
    "manual_review_required": "Manual review required",
    "blocked_before_extract": "Blocked before static analysis",
    "no_security_tool_surface_detected": "No security-tool surface detected",
    "maya_agentic_surface_v0_1": "MAYA agentic surface v0.1",
}

PUBLIC_LABEL_TO_STATE = {
    "Standard static review": PUBLIC_REVIEW,
    "Manual review required": PUBLIC_REVIEW,
    "Blocked before static analysis": PUBLIC_BLOCKED,
}

SECRET_TOKEN_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_\-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9\-]{12,}|AKIA[0-9A-Z]{12,})"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([^'\"\s#&]+)"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.\-])")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}(?!\w)")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
ABS_USER_PATH_RE = re.compile(
    r"(?i)(?:[A-Z]:\\Users\\|/Users/|/home/)([^\\/\s`'\"<>|]+)(?:[\\/][^\s`'\"<>|]*)?"
)
SENSITIVE_REL_PATH_RE = re.compile(
    r"(?i)(?:^|[\\/])(?:home|users)[\\/][^\\/\s`'\"<>|]+[\\/](?:\.aws|\.ssh|\.gnupg|appdata|credentials)(?:[\\/][^\s`'\"<>|]*)?"
)

SENSITIVE_PATH_COMPONENTS = {
    ".aws",
    ".ssh",
    ".gnupg",
    "appdata",
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
}

SENSITIVE_QUERY_KEYS = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|key|apikey|api_key|auth|signature|sig|access|credential)"
)


def public_state(value: Any, *, fallback: str = PUBLIC_REVIEW) -> str:
    text = str(value or "").strip()
    if text in PUBLIC_STATES:
        return text
    return PRIVATE_TO_PUBLIC_STATE.get(text, PUBLIC_LABEL_TO_STATE.get(text, fallback))


def known_public_state(value: Any) -> Any:
    text = str(value or "").strip()
    if text in PUBLIC_STATES:
        return text
    if text in PRIVATE_TO_PUBLIC_STATE:
        return PRIVATE_TO_PUBLIC_STATE[text]
    return value


def public_language(value: str) -> str:
    """Replace bounded internal taxonomy tokens only on public surfaces."""
    text = value
    for token, label in PUBLIC_LANGUAGE_LABELS.items():
        text = text.replace(token, label)
    return text


def _sanitize_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "[REDACTED_URL]"
    hostname = parsed.hostname or ""
    netloc = hostname
    try:
        port = parsed.port
    except ValueError:
        # urlsplit succeeds on `https://host:9100)` but `.port` then raises
        # "Port could not be cast to integer value" because the trailing
        # punctuation was swallowed into the netloc. Never let that crash a
        # sanitization path — drop the port and keep the redacted host.
        port = None
    if port:
        netloc = f"{netloc}:{port}"
    if parsed.username or parsed.password:
        netloc = f"[REDACTED_URL_CREDENTIALS]@{netloc}"
    query_pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query_pairs.append((key, "[REDACTED_QUERY_VALUE]" if SENSITIVE_QUERY_KEYS.search(key) else value))
    # URL fragments are not required for repository identity and can carry
    # OAuth credentials that are not represented in parsed.query.
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query_pairs), ""))


def _sanitize_path_text(text: str) -> str:
    text = ABS_USER_PATH_RE.sub("[USER_PATH]", text)
    text = SENSITIVE_REL_PATH_RE.sub("/[SENSITIVE_PATH]", text)
    if "/" not in text and "\\" not in text:
        return text
    sep = "/" if "/" in text else "\\"
    parts = re.split(r"([\\/])", text)
    sanitized: list[str] = []
    redact_tail = False
    for part in parts:
        if part in {"/", "\\"}:
            if not redact_tail:
                sanitized.append(part)
            continue
        if not part:
            continue
        if redact_tail:
            continue
        if part.lower() in SENSITIVE_PATH_COMPONENTS:
            sanitized.append("[SENSITIVE_PATH]")
            redact_tail = True
            continue
        sanitized.append(part)
    result = "".join(sanitized)
    return result.rstrip("/\\") if "[SENSITIVE_PATH]" in result else text


def sanitize_string(value: str) -> str:
    text = PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY_BLOCK]", value)
    text = URL_RE.sub(_sanitize_url, text)
    text = SECRET_TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    return public_language(_sanitize_path_text(text))


def sanitize_public_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {sanitize_string(str(key)): sanitize_public_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, Path):
        return sanitize_string(value.as_posix())
    if isinstance(value, str):
        return sanitize_string(value)
    return value


def normalize_public_conclusions(value: Any) -> Any:
    data = sanitize_public_value(value)

    def visit(item: Any, parent_key: str = "") -> Any:
        if isinstance(item, dict):
            normalized = {key: visit(val, str(key)) for key, val in item.items()}
            if "status" in normalized:
                normalized["status"] = public_state(normalized.get("status"))
            if "status_label" in normalized:
                normalized["status_label"] = public_state(normalized.get("status_label"))
            if "urgency" in normalized:
                normalized["urgency"] = public_state(normalized.get("urgency"))
            if "posture" in normalized:
                normalized["posture"] = known_public_state(normalized.get("posture"))
            if parent_key == "axis_statuses":
                return {key: public_state(val) for key, val in normalized.items()}
            return normalized
        if isinstance(item, list):
            return [visit(entry, parent_key) for entry in item]
        if parent_key in {"status", "status_label", "urgency"}:
            return public_state(item)
        return item

    return visit(data)


class _AnyPublicValue:
    pass


PUBLIC_ANY = _AnyPublicValue()

PUBLIC_SCALAR = (str, int, float, bool, type(None))


def _is_public_scalar(value: Any) -> bool:
    return isinstance(value, PUBLIC_SCALAR)


def _project_public_list(value: Any, item_schema: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    projected: list[Any] = []
    for item in value:
        public_item = _project_public_value(item, item_schema)
        if public_item not in (None, {}, []):
            projected.append(public_item)
    return projected


def _project_public_map(value: Any, item_schema: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    projected: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = sanitize_string(str(key))
        public_item = _project_public_value(item, item_schema)
        if public_item not in (None, {}, []):
            projected[safe_key] = public_item
    return projected


def _project_public_value(value: Any, schema: Any) -> Any:
    if schema is PUBLIC_ANY:
        if _is_public_scalar(value):
            return sanitize_public_value(value)
        if isinstance(value, Path):
            return sanitize_public_value(value)
        if isinstance(value, list):
            return [item for item in (sanitize_public_value(v) for v in value) if _is_public_scalar(item)]
        if isinstance(value, dict):
            return {
                sanitize_string(str(key)): sanitize_public_value(item)
                for key, item in value.items()
                if _is_public_scalar(item)
            }
        return None
    if schema is str:
        return sanitize_string(value.as_posix() if isinstance(value, Path) else str(value)) if value is not None else ""
    if schema is bool:
        return bool(value)
    if schema is int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    if schema is float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
    if isinstance(schema, tuple) and schema:
        kind = schema[0]
        if kind == "list":
            return _project_public_list(value, schema[1])
        if kind == "map":
            return _project_public_map(value, schema[1])
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            return {}
        projected = {}
        for key, child_schema in schema.items():
            if key in value:
                public_item = _project_public_value(value[key], child_schema)
                if public_item not in (None, {}, []):
                    projected[key] = public_item
        return projected
    return None


PUBLIC_FINDING_SCHEMA = {
    "category": str,
    "severity": str,
    "path": str,
    "line": PUBLIC_ANY,
    "signal": str,
    "snippet": str,
}

PUBLIC_AXIS_SCHEMA = {
    "value": PUBLIC_ANY,
    "direction": str,
    "confidence": str,
    "interpretation": str,
    "color": str,
    "status_label": str,
    "reward_note": str,
    "review_options": ("list", str),
}

PUBLIC_COMPONENT_SCHEMA = {
    "type": str,
    "path": str,
    "reason": str,
}

PUBLIC_SIGNAL_SCHEMA = {
    "id": str,
    "label": str,
    "path": str,
    "signal": str,
    "recommended_action": str,
}

PUBLIC_EVIDENCE_SCHEMA = {
    "path": str,
    "line": PUBLIC_ANY,
    "snippet": str,
}

PUBLIC_AUTHORITY_CLASS_SCHEMA = {
    "id": str,
    "label": str,
    "evidence_count": int,
    "sample_evidence": ("list", PUBLIC_EVIDENCE_SCHEMA),
    "recommended_action": str,
}

PUBLIC_REPORT_SCHEMA = {
    "markdown": str,
    "html": str,
    "json": str,
}

PUBLIC_PROJECTION_SCHEMA = {
    "tool": str,
    "version": str,
    "fence": str,
    "disclaimer": str,
    "started_at": str,
    "completed_at": str,
    "source_zip": str,
    "source_sha256": str,
    "status": str,
    "summary": {
        "headline": str,
        "next_step": str,
        "not_checked": ("list", str),
    },
    "metadata": {
        "repo_identity": str,
        "source_url": PUBLIC_ANY,
        "license": PUBLIC_ANY,
        "readme_title": PUBLIC_ANY,
        "provenance_signals": ("list", str),
    },
    "inventory": {
        "file_count": int,
        "dir_count": int,
        "total_bytes": int,
        "total_mb": PUBLIC_ANY,
        "extensions": ("map", PUBLIC_ANY),
        "largest_files": ("list", {"path": str, "bytes": int}),
        "special": ("map", PUBLIC_ANY),
    },
    "governance_surface": {
        "version": str,
        "counts": ("map", PUBLIC_ANY),
        "approval_docs": ("list", PUBLIC_SIGNAL_SCHEMA),
        "workflow_signals": ("list", PUBLIC_SIGNAL_SCHEMA),
        "maintenance_signals": ("list", PUBLIC_SIGNAL_SCHEMA),
    },
    "security_tool_surface": {
        "version": str,
        "posture": str,
        "human_scope_required": bool,
        "counts": ("map", PUBLIC_ANY),
        "signals": ("list", PUBLIC_SIGNAL_SCHEMA),
        "recommended_review_actions": ("list", str),
    },
    "ai_bom": {
        "version": str,
        "component_count": int,
        "dependency_direct_count": int,
        "component_type_counts": ("map", PUBLIC_ANY),
        "dependency_ecosystems": ("map", PUBLIC_ANY),
        "components": ("list", PUBLIC_COMPONENT_SCHEMA),
    },
    "artifact_receipt": {
        "version": str,
        "input_name": str,
        "sha256": str,
        "repo_identity": PUBLIC_ANY,
        "source_url": PUBLIC_ANY,
        "file_count": int,
        "total_mb": PUBLIC_ANY,
        "ai_component_count": int,
        "component_type_counts": ("map", PUBLIC_ANY),
        "manifest_file_count": int,
        "lockfile_count": int,
        "install_hook_count": int,
        "archive_safety": {
            "status": str,
            "blocked_reason": PUBLIC_ANY,
            "extraction_metrics": {
                "file_count": int,
                "total_extracted_bytes": int,
                "total_declared_uncompressed_bytes": int,
                "total_declared_compressed_bytes": int,
                "max_compression_ratio": PUBLIC_ANY,
            },
        },
        "static_only": bool,
        "executed_repo_code": bool,
        "installed_dependencies": bool,
        "network_calls": bool,
    },
    "finding_groups": ("list", {
        "count": int,
        "max_severity": str,
        "category": str,
        "signal": str,
        "sample_paths": ("list", str),
    }),
    "remediation_plan": ("list", {
        "priority": int,
        "category": str,
        "action": str,
    }),
    "advisory_triage": {
        "version": str,
        "urgency": str,
        "owner": str,
        "summary": str,
        "primary_focus": ("list", str),
        "top_categories": ("list", {
            "category": str,
            "signal": str,
            "count": int,
            "max_severity": str,
        }),
        "recommended_actions": ("list", str),
    },
    "agentic_surface": {
        "version": str,
        "posture": str,
        "owner": str,
        "component_counts": ("map", PUBLIC_ANY),
        "surfaces": ("list", {
            "surface": str,
            "label": str,
            "count": int,
        }),
        "policy_checks": ("list", {
            "surface": str,
            "check": str,
        }),
    },
    "action_boundary_review": {
        "version": str,
        "decision": str,
        "manual_approval_required": bool,
        "authority_classes": ("list", PUBLIC_AUTHORITY_CLASS_SCHEMA),
        "recommended_actions": ("list", str),
        "instruction_surface_integrity": {
            "status": str,
            "agent_instruction_count": int,
            "mcp_server_count": int,
            "workflow_automation_count": int,
            "approval_doc_count": int,
            "checks": ("list", str),
        },
    },
    "security_routing": {
        "version": str,
        "tier1_screen": str,
        "decision": str,
        "recommended_lane": str,
        "human_gate_required": bool,
        "why": ("list", str),
    },
    "axes": ("map", PUBLIC_AXIS_SCHEMA),
    "findings": ("list", PUBLIC_FINDING_SCHEMA),
    "public_receipt": {
        "version": str,
        "tool": str,
        "source_zip": str,
        "source_sha256": str,
        "completed_at": str,
        "status": str,
        "disclaimer": str,
        "static_only": bool,
        "executed_repo_code": bool,
        "installed_dependencies": bool,
        "network_calls": bool,
        "archive_safety": str,
        "review_decision": str,
        "human_gate_required": bool,
        "review_route": str,
        "axis_statuses": ("map", str),
        "finding_count": int,
        "component_count": int,
        "action_boundaries": ("list", str),
        "security_tool_surface": {
            "posture": str,
            "human_scope_required": bool,
            "counts": ("map", PUBLIC_ANY),
        },
        "recommended_actions": ("list", str),
        "fence": str,
    },
    "reports": PUBLIC_REPORT_SCHEMA,
}


def build_public_projection(result: dict[str, Any]) -> dict[str, Any]:
    projected = _project_public_value(result, PUBLIC_PROJECTION_SCHEMA)
    projected = normalize_public_conclusions(projected)
    public_receipt = projected.get("public_receipt") if isinstance(projected, dict) else {}
    if isinstance(public_receipt, dict):
        public_receipt["version"] = PUBLIC_RECEIPT_VERSION
    return projected
