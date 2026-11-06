"""dashboard/plugin_api.py — READ-ONLY GET only (F2). No POST mutations."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from fastapi import APIRouter
router = APIRouter()

def _db_path():
    import os
    return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))) / "plugin-data" / "file-intelligence" / "file_intelligence.db"

def _rows(sql, args=()):
    p = _db_path()
    if not p.exists(): return []
    conn = sqlite3.connect(str(p), check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    try: return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except sqlite3.Error: return []
    finally: conn.close()

@router.get("/status")
def status():
    scans = _rows("SELECT * FROM scans ORDER BY created_at DESC LIMIT 5")
    total_reclaim = sum(r.get("reclaimable_bytes") or 0 for r in _rows("SELECT reclaimable_bytes FROM proposals WHERE status='proposed'"))
    return {"ok": True, "recent_scans": scans, "reclaimable_bytes": total_reclaim}

@router.get("/proposals")
def proposals():
    return {"ok": True, "proposals": _rows("SELECT * FROM proposals ORDER BY created_at DESC LIMIT 50")}

@router.get("/audit")
def audit():
    return {"ok": True, "audit": _rows("SELECT * FROM audit ORDER BY id DESC LIMIT 50")}
