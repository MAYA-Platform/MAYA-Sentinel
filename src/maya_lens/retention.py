from __future__ import annotations

import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from .public_safety import PUBLIC_RECEIPT_VERSION, build_public_projection, public_state

HISTORY_VERSION = "maya_sentinel_retained_history_v0_2"
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,160}$")


def validate_scan_id(scan_id: str) -> str:
    value = str(scan_id or "").strip()
    if not SCAN_ID_RE.fullmatch(value) or ".." in value:
        raise ValueError("invalid_scan_id")
    return value


def history_record(result: dict[str, Any], reports: dict[str, str]) -> dict[str, Any]:
    public_result = build_public_projection(result)
    public_reports = build_public_projection({"reports": reports}).get("reports", {})
    scan_id_source = public_reports.get("json") or public_reports.get("markdown") or public_reports.get("html") or uuid.uuid4().hex
    scan_id = validate_scan_id(Path(scan_id_source).stem)
    public_receipt = public_result.get("public_receipt", {})
    return {
        "history_version": HISTORY_VERSION,
        "scan_id": scan_id,
        "input_sha256": public_result.get("source_sha256", ""),
        "completed_at": public_result.get("completed_at", ""),
        "approved_final_state": public_state(public_result.get("status")),
        "reports": public_reports,
        "product_version": public_result.get("version", "0.2.0"),
        "public_receipt_version": public_receipt.get("version", PUBLIC_RECEIPT_VERSION),
        "sanitizer_public_receipt_version": PUBLIC_RECEIPT_VERSION,
    }


class RetainedScanHistory:
    """Process-local retained public receipt history.

    The lock and atomic replace protect history consistency inside this Python
    process. They are not cross-process coordination. Running two server
    processes against the same data directory is unsupported for retention.
    """

    def __init__(self, history_path: str | Path, reports_dir: str | Path):
        self.history_path = Path(history_path)
        self.reports_dir = Path(reports_dir)
        self._lock = threading.Lock()

    def _read_unlocked(self) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        text = self.history_path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [row for row in data if isinstance(row, dict)]
        except json.JSONDecodeError:
            pass

        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def _write_unlocked(self, rows: list[dict[str, Any]]) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.history_path.with_name(f".{self.history_path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temp_path.open("x", encoding="utf-8", newline="") as f:
                json.dump(rows, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.history_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def list(self, limit: int | None = 6) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._read_unlocked()
        ordered = list(reversed(rows))
        return ordered if limit is None else ordered[:limit]

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        scan_id = validate_scan_id(str(record.get("scan_id", "")))
        with self._lock:
            rows = [row for row in self._read_unlocked() if row.get("scan_id") != scan_id]
            rows.append(record)
            self._write_unlocked(rows)
        return record

    def _report_path(self, name: Any) -> Path:
        text = str(name or "")
        if not text or Path(text).name != text or "/" in text or "\\" in text:
            raise ValueError("invalid_report_path")
        root = self.reports_dir.resolve()
        target = (root / text).resolve()
        if root not in target.parents and target != root:
            raise ValueError("invalid_report_path")
        return target

    def delete_one(self, scan_id: str) -> dict[str, Any]:
        target_id = validate_scan_id(scan_id)
        with self._lock:
            rows = self._read_unlocked()
            target = next((row for row in rows if row.get("scan_id") == target_id), None)
            if target is None:
                return {"deleted": False, "scan_id": target_id, "reports_deleted": 0}
            report_paths = [self._report_path(name) for name in dict(target.get("reports", {})).values()]
            deleted_count = 0
            for path in report_paths:
                if path.exists():
                    path.unlink()
                    deleted_count += 1
            self._write_unlocked([row for row in rows if row.get("scan_id") != target_id])
        return {"deleted": True, "scan_id": target_id, "reports_deleted": deleted_count}

    def clear(self) -> dict[str, Any]:
        with self._lock:
            rows = self._read_unlocked()
            paths: list[Path] = []
            for row in rows:
                for name in dict(row.get("reports", {})).values():
                    paths.append(self._report_path(name))
            deleted_count = 0
            for path in paths:
                if path.exists():
                    path.unlink()
                    deleted_count += 1
            self._write_unlocked([])
        return {"deleted": True, "scan_count": len(rows), "reports_deleted": deleted_count}
