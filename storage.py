"""storage.py — SQLite store in ctx.state.data_dir. Metadata only, never file content."""
from __future__ import annotations
import sqlite3, threading
from pathlib import Path
SCHEMA_VERSION = 1
_lock = threading.RLock()

def open_db(data_dir):
    p = Path(data_dir); p.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p / "file_intelligence.db"), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    return conn

def init_db(conn):
    with _lock:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
          scan_id TEXT PRIMARY KEY, root TEXT NOT NULL, created_at TEXT NOT NULL,
          file_count INT, total_bytes INT, status TEXT
        );
        CREATE TABLE IF NOT EXISTS proposals(
          proposal_id TEXT PRIMARY KEY, scan_id TEXT, kind TEXT, risk TEXT,
          paths TEXT, reclaimable_bytes INT, status TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_files(scan_id TEXT PRIMARY KEY, files_json TEXT);
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, detail TEXT
        );
        """)
        conn.commit()

def prune(conn, max_audit=10000):
    with _lock:
        conn.execute("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)", (max_audit,))
        conn.commit()
