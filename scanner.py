"""scanner.py — read-only directory scan. Stat + chunked hash, never file content.
Hidden directories (dot-dirs) are excluded wholesale; hidden files at scanned root (e.g. .env) are included and flagged sensitive. Sensitive files are NEVER hashed."""
from __future__ import annotations
import hashlib, os
from pathlib import Path

SENSITIVE_NAMES = {".env", "id_rsa", "id_ed25519", ".pem", ".key", "credentials.json", ".netrc"}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".hermes", ".venv", "venv"}
MAX_FILES = 10000
CHUNK = 1024 * 1024
MAX_HASH_BYTES = 1024 * 1024 * 1024  # skip hashing >1GB, note it

def is_sensitive(name: str) -> bool:
    n = Path(name).name.lower()
    return n in SENSITIVE_NAMES or n.endswith(SENSITIVE_SUFFIXES) or n.startswith(".env")

def is_sensitive_path(path) -> bool:
    """Shared policy for scanner + apply. Use everywhere."""
    return is_sensitive(str(path))

def hash_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

def scan(root: str, max_depth: int = 6, ignore: list | None = None, cursor: int = 0):
    """Returns dict with files list, truncated flag, next_cursor. Read-only."""
    rootp = Path(root).expanduser()
    if not rootp.exists() or not rootp.is_dir():
        return {"ok": False, "error": f"root not found or not a directory: {root}"}
    # Path safety: refuse system dirs unless explicitly same root (caller responsibility documented)
    files = []
    total = 0
    seen = 0
    ignore_set = set(ignore or []) | IGNORE_DIRS
    for dirpath, dirnames, filenames in os.walk(rootp):
        depth = len(Path(dirpath).relative_to(rootp).parts)
        dirnames[:] = [d for d in dirnames if d not in ignore_set and not d.startswith(".")]
        if depth > max_depth:
            continue
        for fn in filenames:
            seen += 1
            if seen <= cursor:
                continue
            fp = Path(dirpath) / fn
            try:
                st = fp.stat()
            except OSError:
                continue
            if not fp.is_file() or fp.is_symlink():
                continue
            total += st.st_size
            files.append({
                "path": str(fp), "name": fn, "size": st.st_size,
                "sensitive": is_sensitive(fn),
                "hash": ("sensitive-not-hashed" if is_sensitive(fn) else (hash_file(fp) if st.st_size > 0 else "empty")),
            })
            if len(files) >= MAX_FILES:
                return {"ok": True, "files": files, "total_bytes": total, "truncated": True, "next_cursor": seen, "scanned": seen}
    return {"ok": True, "files": files, "total_bytes": total, "truncated": False, "next_cursor": seen, "scanned": seen}
