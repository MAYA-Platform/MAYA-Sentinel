"""
universal_scan.py — Universal archive dispatcher for MAYA Sentinel.

Extends scan_zip to handle any file type:
  - Archives (.zip, .jar, .war, .ear, .kmz, .oxt) → normal scan
  - Installers/binaries (.exe, .msi, .msix, .app, .dmg, .apk, .aab, .deb, .rpm, .pkg, .snap) → try zip, fallback to binary surface
  - Everything else → try zip, fallback to generic static
  - Corrupt/unreadable → clean error receipt, never a crash

Zero new dependencies. Pure stdlib. Drop-in alongside scanner.py and public_safety.py.
"""

from __future__ import annotations

import mimetypes
import zipfile
from pathlib import Path
from typing import Any

# Common archive extensions that zipfile can handle
ARCHIVE_EXTENSIONS = {".zip", ".jar", ".war", ".ear", ".kmz", ".oxt", ".xlsx", ".docx", ".pptx"}

# Extensions that might be ZIP-based installers or binary blobs
INSTALLER_EXTENSIONS = {".exe", ".msi", ".msix", ".app", ".dmg", ".apk", ".aab", ".deb", ".rpm", ".pkg", ".snap"}

# Compressed tar variants — not directly zipfile-compatible, but we try
TAR_EXTENSIONS = {".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst", ".gz", ".bz2", ".xz", ".zst"}


def universal_scan(path: str | Path) -> dict[str, Any]:
    """
    Scan any file path, routing to the right handler based on extension and content.
    Returns a dict with at minimum: ok, signal, summary, and file_type fields.
    """
    path = Path(path)
    
    if not path.exists():
        return _error_result(f"File not found: {path}")
    
    if not path.is_file():
        return _error_result(f"Not a file: {path}")
    
    ext = _get_ext(path)
    
    # Try importing scanner lazily so this module loads without deps
    try:
        from maya_lens.scanner import scan_zip
    except ImportError:
        return _error_result("scanner module not available (src/maya_lens/scanner.py missing)")
    
    # 1. Known ZIP-compatible archives → direct scan
    if ext in ARCHIVE_EXTENSIONS:
        try:
            return scan_zip(path)
        except Exception as e:
            return _error_result(f"Archive scan failed: {e}")
    
    # 2. Installers/binaries → try ZIP extraction first, fall back to binary scan
    if ext in INSTALLER_EXTENSIONS:
        result = _try_scan_as_zip(path, scan_zip)
        if result is not None:
            return result
        # Fallback: basic binary surface scan
        return _binary_surface_scan(path)
    
    # 3. Tarballs → not directly zipfile-compatible
    if ext in TAR_EXTENSIONS:
        return _result("Review", f"Tarball detected ({ext}). Sentinel's scanner doesn't extract tarballs directly — uncompress and scan the inner archive.")
    
    # 4. Unknown extension → try ZIP anyway, fallback to binary scan
    result = _try_scan_as_zip(path, scan_zip)
    if result is not None:
        return result
    
    # 5. Generic binary fallback
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        if header[:2] == b"PK":
            # ZIP header present but zipfile failed — corrupt archive
            return _error_result("File has ZIP header but is not a valid archive (corrupt or truncated)")
        else:
            return _binary_surface_scan(path)
    except Exception as e:
        return _error_result(f"Cannot read file: {e}")


def _try_scan_as_zip(path: Path, scan_zip_fn) -> dict[str, Any] | None:
    """Try to open as a ZIP and scan. Returns None if it's not a valid ZIP."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            if not infos:
                return None
            return scan_zip_fn(path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError):
        return None
    except Exception:
        return None


def _binary_surface_scan(path: Path) -> dict[str, Any]:
    """Basic static analysis for binary files that aren't ZIP archives."""
    size = path.stat().st_size
    
    try:
        with open(path, "rb") as f:
            header = f.read(256)
    except Exception:
        header = b""
    
    file_type = _detect_binary_type(header)
    
    return {
        "ok": True,
        "signal": "No signal",
        "summary": f"Binary file ({file_type}). Static analysis limited to file-level metadata — no code surface to inspect.",
        "file_type": file_type,
        "size_bytes": size,
        "extracted_files": 0,
        "findings": [],
        "provenance": {"signals": []},
        "governance": {"signals": []},
        "security_tools": {"signals": []},
        "ai_agent_surfaces": {"signals": []},
        "persistence": {"signals": []},
        "credentials": {"signals": []},
    }


def _detect_binary_type(header: bytes) -> str:
    """Identify file type from magic bytes."""
    if header[:2] == b"MZ":
        return "Windows executable (PE)"
    if header[:4] == b"\xca\xfe\xba\xbe":
        return "Java class file"
    if header[:4] == b"\xcf\xfa\xed\xfe":
        return "Mach-O (macOS binary)"
    if header[:8] == b"\xfe\xed\xfa\xce" or header[:8] == b"\xce\xfa\xed\xfe":
        return "Mach-O (macOS binary)"
    if header[:3] == b"\x7fELF":
        return "ELF (Linux binary)"
    if header[:4] == b"\x00\x01\x00\x00" or header[:4] == b"\x00\x02\x00\x00":
        return "Windows Portable Executable (.NET)"
    if header[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image (not an archive)"
    if header[:4] == b"\x25\x50\x44\x46":
        return "PDF document (not an archive)"
    mime, _ = mimetypes.guess_type("x")
    return mime or "Unknown binary"


def _get_ext(path: Path) -> str:
    """Get the file extension, handling compound extensions like .tar.gz."""
    name = path.name.lower()
    for compound in [".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"]:
        if name.endswith(compound):
            return compound
    return path.suffix.lower()


def _result(signal: str, summary: str, **extra: Any) -> dict[str, Any]:
    """Build a clean result dict matching Sentinel's public-safe schema."""
    return {
        "ok": True,
        "signal": signal,
        "summary": summary,
        **extra,
    }


def _error_result(message: str) -> dict[str, Any]:
    """Build an error result that won't crash the server."""
    return {
        "ok": False,
        "signal": "Review",
        "summary": message,
        "error": message,
        "findings": [],
        "provenance": {"signals": []},
        "governance": {"signals": []},
        "security_tools": {"signals": []},
        "ai_agent_surfaces": {"signals": []},
        "persistence": {"signals": []},
        "credentials": {"signals": []},
    }
