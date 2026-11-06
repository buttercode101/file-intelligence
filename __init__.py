"""File Intelligence — proactive scan + proposals. No silent modify/move/delete.

Design (red-team F2-F4):
- Scan is read-only (stat + hash). Content never stored.
- Dry-run default. Real apply only via file_apply tool (approval path), never Desktop POST.
- Sensitive flagged only, never moved.
- Apply = archive (rename) to <root>/.file-intelligence-archive/, reversible.
"""
from __future__ import annotations
import json, os, sys, time, uuid
from pathlib import Path

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

try:
    from .storage import init_db, open_db, prune
    from .scanner import scan as _scan
    from .proposals import build_proposals
except ImportError:
    from storage import init_db, open_db, prune
    from scanner import scan as _scan
    from proposals import build_proposals

_ctx = None

def _data_dir():
    if _ctx is not None:
        return _ctx.state.data_dir
    return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))) / "plugin-data" / "file-intelligence"

def _db():
    conn = open_db(_data_dir()); init_db(conn); return conn

def _now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _audit(action, detail):
    try:
        conn = _db()
        try:
            conn.execute("INSERT INTO audit(ts,action,detail) VALUES(?,?,?)", (_now(), action, detail[:500]))
            prune(conn); conn.commit()
        finally: conn.close()
    except Exception: pass

def handle_scan(args=None, **kw):
    args = args or {}
    root = args.get("root") or ""
    if not root:
        return json.dumps({"ok": False, "error": "root is required"})
    result = _scan(root, max_depth=int(args.get("max_depth") or 6), ignore=args.get("ignore") or [], cursor=int(args.get("cursor") or 0))
    if not result.get("ok"):
        return json.dumps(result)
    scan_id = "scan_" + uuid.uuid4().hex[:8]
    conn = _db()
    try:
        conn.execute("INSERT INTO scans(scan_id,root,created_at,file_count,total_bytes,status) VALUES(?,?,?,?,?,?)",
                     (scan_id, root, _now(), len(result["files"]), result["total_bytes"], "complete"))
        conn.commit()
    finally: conn.close()
    _audit("scan", f"{scan_id} root={root} files={len(result['files'])} bytes={result['total_bytes']}")
    # Return summary, not full file list (cap 200 in response)
    return json.dumps({"ok": True, "scan_id": scan_id, "file_count": len(result["files"]), "total_bytes": result["total_bytes"],
                       "truncated": result["truncated"], "next_cursor": result["next_cursor"],
                       "files": result["files"][:200]})

def handle_propose(args=None, **kw):
    args = args or {}
    # Re-scan root to build proposals (stateless, no content stored)
    root = args.get("root") or ""
    if not root:
        return json.dumps({"ok": False, "error": "root is required"})
    result = _scan(root, max_depth=int(args.get("max_depth") or 6))
    if not result.get("ok"):
        return json.dumps(result)
    proposals = build_proposals(result["files"])
    conn = _db()
    try:
        for p in proposals:
            pid = "prop_" + uuid.uuid4().hex[:8]
            conn.execute("INSERT INTO proposals(proposal_id,scan_id,kind,risk,paths,reclaimable_bytes,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                         (pid, args.get("scan_id") or "", p["kind"], p["risk"], json.dumps(p.get("archive", []) + p.get("flag_only", [])), p["reclaimable_bytes"], "proposed", _now()))
        conn.commit()
    finally: conn.close()
    _audit("propose", f"root={root} proposals={len(proposals)} reclaimable={sum(p['reclaimable_bytes'] for p in proposals)}")
    return json.dumps({"ok": True, "proposals": proposals, "reclaimable_bytes": sum(p["reclaimable_bytes"] for p in proposals)})

def handle_apply(args=None, **kw):
    """Dry-run default. Real apply requires dry_run=false AND goes through approval (tool path).
    Action: archive (rename) to <root>/.file-intelligence-archive/. Never permanent delete.
    Sensitive paths are refused."""
    args = args or {}
    dry_run = args.get("dry_run", True)
    paths = args.get("paths") or []
    root = args.get("root") or ""
    if not paths:
        return json.dumps({"ok": False, "error": "paths[] is required"})
    # Refuse sensitive
    for p in paths:
        name = Path(p).name.lower()
        if name.startswith(".env") or name.endswith((".pem",".key",".p12",".pfx")) or name in ("id_rsa","id_ed25519"):
            return json.dumps({"ok": False, "error": f"refused: sensitive path flagged only, never moved: {p}"})
    if dry_run:
        _audit("apply_dry_run", f"paths={len(paths)}")
        return json.dumps({"ok": True, "dry_run": True, "would_archive": paths, "note": "dry-run only — no files moved. Set dry_run=false via agent tool (approval required) to apply."})
    # Real apply: archive via rename
    archive_root = Path(root) / ".file-intelligence-archive" if root else None
    results = []
    for src in paths:
        sp = Path(src).expanduser()
        try:
            if not sp.exists():
                results.append({"path": src, "ok": False, "error": "not found"}); continue
            if archive_root is None:
                results.append({"path": src, "ok": False, "error": "root required for archive target"}); continue
            archive_root.mkdir(parents=True, exist_ok=True)
            dest = archive_root / sp.name
            if dest.exists():
                dest = archive_root / f"{sp.stem}_{uuid.uuid4().hex[:6]}{sp.suffix}"
            sp.rename(dest)
            results.append({"path": src, "ok": True, "archived_to": str(dest)})
        except OSError as e:
            results.append({"path": src, "ok": False, "error": str(e)})
    _audit("apply", f"paths={len(paths)} results={json.dumps(results)[:400]}")
    return json.dumps({"ok": True, "dry_run": False, "results": results})

def _on_post_tool_call(tool_name="", args=None, **kwargs):
    try:
        if tool_name in ("file_apply",):
            _audit("post_tool_call", tool_name)
    except Exception: pass

def register(ctx):
    global _ctx; _ctx = ctx
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    base = {"type": "object", "properties": {}, "required": []}
    ctx.register_tool(name="file_scan", toolset="file_intelligence",
        schema={**base, "properties": {"root": {"type": "string"}, "max_depth": {"type": "integer"}, "ignore": {"type": "array"}, "cursor": {"type": "integer"}}, "required": ["root"]},
        handler=handle_scan, emoji="🔍")
    ctx.register_tool(name="file_propose", toolset="file_intelligence",
        schema={**base, "properties": {"root": {"type": "string"}, "scan_id": {"type": "string"}, "max_depth": {"type": "integer"}}, "required": ["root"]},
        handler=handle_propose, emoji="📋")
    ctx.register_tool(name="file_apply", toolset="file_intelligence",
        schema={**base, "properties": {"paths": {"type": "array"}, "root": {"type": "string"}, "dry_run": {"type": "boolean"}}, "required": ["paths"]},
        handler=handle_apply, emoji="🗂️")
