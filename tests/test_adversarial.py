"""Adversarial gate tests for P0/P1 blockers. Run: python3 tests/test_adversarial.py"""
import json, os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="fi-adv-")
from scanner import scan, is_sensitive_path
from __init__ import handle_scan, handle_propose, handle_apply

def _messy():
    d = Path(tempfile.mkdtemp(prefix="fi-adv-messy-"))
    (d/"a.txt").write_text("hello world")
    (d/"b.txt").write_text("hello world")
    (d/".env").write_text("SECRET=1")
    (d/".netrc").write_text("machine x")
    (d/"credentials.json").write_text("{}")
    return d

def test_sensitive_never_hashed():
    d=_messy(); r=scan(str(d))
    for f in r["files"]:
        if f["name"] in (".env", ".netrc", "credentials.json"):
            assert f["hash"] == "sensitive-not-hashed", (f["name"], f["hash"])
            assert f["sensitive"] == True
    print("P0 sensitive_never_hashed OK")

def test_shared_sensitive_policy():
    # .netrc and credentials.json must be refused by apply (previously only scanner flagged them)
    d=_messy()
    for name in (".env", ".netrc", "credentials.json"):
        out=json.loads(handle_apply({"paths":[str(d/name)],"root":str(d),"dry_run":False}))
        assert not out["ok"] and "sensitive" in out["error"], (name, out)
        assert (d/name).exists()
    print("P0 shared_sensitive_policy OK")

def test_path_traversal():
    d=_messy()
    outside = Path(tempfile.mkdtemp(prefix="fi-outside-")) / "evil.txt"
    outside.write_text("evil")
    out=json.loads(handle_apply({"paths":[str(outside)],"root":str(d),"dry_run":False}))
    assert not out["ok"] and "outside" in out["error"], out
    assert outside.exists()
    print("P0 path_traversal OK")

def test_symlink_archive_refused():
    d=_messy()
    target = Path(tempfile.mkdtemp(prefix="fi-target-"))
    (target/"keep.txt").write_text("x")
    archive = d/".file-intelligence-archive"
    archive.symlink_to(target, target_is_directory=True)
    out=json.loads(handle_apply({"paths":[str(d/"a.txt")],"root":str(d),"dry_run":False}))
    assert not out["ok"] and "symlink" in out["error"].lower(), out
    assert (d/"a.txt").exists()
    print("P0 symlink_archive_refused OK")

def test_symlink_source_refused():
    d=_messy()
    link = d/"link.txt"
    link.symlink_to(d/"a.txt")
    out=json.loads(handle_apply({"paths":[str(link)],"root":str(d),"dry_run":False}))
    assert not out["ok"] and "symlink" in out["error"].lower(), out
    print("P0 symlink_source_refused OK")

def test_scan_proposal_binding():
    d=_messy()
    s=json.loads(handle_scan({"root":str(d)}))
    assert s["ok"], s
    scan_id=s["scan_id"]
    p=json.loads(handle_propose({"scan_id":scan_id}))
    assert p["ok"] and p["proposals"], p
    # Wrong root must fail
    other=Path(tempfile.mkdtemp())
    p2=json.loads(handle_propose({"scan_id":scan_id,"root":str(other)}))
    assert not p2["ok"] and "does not match" in p2["error"], p2
    # Unknown scan must fail
    p3=json.loads(handle_propose({"scan_id":"scan_deadbeef"}))
    assert not p3["ok"] and "unknown" in p3["error"], p3
    print("P1 scan_proposal_binding OK")

if __name__=="__main__":
    test_sensitive_never_hashed()
    test_shared_sensitive_policy()
    test_path_traversal()
    test_symlink_archive_refused()
    test_symlink_source_refused()
    test_scan_proposal_binding()
    print("ALL ADVERSARIAL TESTS PASS")
