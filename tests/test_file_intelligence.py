import os, sys, tempfile, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="fi-test-")
from scanner import scan, is_sensitive
from proposals import build_proposals
from __init__ import handle_scan, handle_propose, handle_apply

def _messy():
    d = Path(tempfile.mkdtemp(prefix="fi-messy-"))
    (d/"a.txt").write_text("hello world")
    (d/"b.txt").write_text("hello world")  # duplicate
    (d/".env").write_text("SECRET=1")
    (d/"big.bin").write_bytes(b"x" * (2*1024*1024))
    return d

def test_scan():
    d=_messy(); r=scan(str(d))
    assert r["ok"], r
    names={f["name"] for f in r["files"]}
    assert {"a.txt","b.txt",".env","big.bin"} <= names, names
    env=[f for f in r["files"] if f["name"]==".env"][0]
    assert env["sensitive"]==True
    print("test_scan OK")

def test_propose():
    d=_messy(); r=scan(str(d)); props=build_proposals(r["files"])
    kinds={p["kind"] for p in props}
    assert "duplicate" in kinds and "sensitive" in kinds, kinds
    sens=[p for p in props if p["kind"]=="sensitive"][0]
    assert sens["archive"]==[]  # flag only
    print("test_propose OK", kinds)

def test_apply_dry_run():
    d=_messy()
    out=json.loads(handle_apply({"paths":[str(d/"a.txt")],"root":str(d),"dry_run":True}))
    assert out["ok"] and out["dry_run"]==True
    assert (d/"a.txt").exists()  # dry-run must not move
    print("test_apply_dry_run OK")

def test_apply_refuses_sensitive():
    d=_messy()
    out=json.loads(handle_apply({"paths":[str(d/".env")],"root":str(d),"dry_run":False}))
    assert not out["ok"] and "sensitive" in out["error"], out
    assert (d/".env").exists()
    print("test_apply_refuses_sensitive OK")

def test_apply_archive():
    d=_messy()
    out=json.loads(handle_apply({"paths":[str(d/"b.txt")],"root":str(d),"dry_run":False}))
    assert out["ok"] and out["results"][0]["ok"], out
    assert not (d/"b.txt").exists()
    assert (d/".file-intelligence-archive/b.txt").exists()
    print("test_apply_archive OK")

if __name__=="__main__":
    test_scan(); test_propose(); test_apply_dry_run(); test_apply_refuses_sensitive(); test_apply_archive()
    print("ALL TESTS PASS")
