"""proposals.py — rank safe actions from scan results. Pure, no IO."""
from __future__ import annotations
from collections import defaultdict

def build_proposals(files: list) -> list:
    proposals = []
    # Duplicates: same hash, keep first (largest path sorted), propose archive rest
    by_hash = defaultdict(list)
    for f in files:
        if f.get("hash") and f["hash"] not in ("empty",):
            by_hash[f["hash"]].append(f)
    for h, group in by_hash.items():
        if len(group) < 2: continue
        group_sorted = sorted(group, key=lambda x: x["path"])
        keep, dupes = group_sorted[0], group_sorted[1:]
        reclaim = sum(d["size"] for d in dupes)
        proposals.append({
            "kind": "duplicate", "risk": "low",
            "keep": keep["path"], "archive": [d["path"] for d in dupes],
            "reclaimable_bytes": reclaim,
            "detail": f"{len(dupes)} duplicate(s) of {keep['path']} (hash {h[:8]}…)",
        })
    # Large files >100MB (flag for review, propose archive)
    LARGE = 100 * 1024 * 1024
    large = [f for f in files if f["size"] > LARGE and not f["sensitive"]]
    for f in sorted(large, key=lambda x: -x["size"])[:20]:
        proposals.append({
            "kind": "large", "risk": "medium", "archive": [f["path"]],
            "reclaimable_bytes": f["size"],
            "detail": f"Large file {f['size']//(1024*1024)}MB: {f['path']}",
        })
    # Sensitive: flag ONLY, never propose move/delete
    sens = [f for f in files if f["sensitive"]]
    for f in sens:
        proposals.append({
            "kind": "sensitive", "risk": "high", "archive": [],
            "flag_only": [f["path"]], "reclaimable_bytes": 0,
            "detail": f"SENSITIVE — flagged only, never auto-moved: {f['path']}",
        })
    # Rank: low risk first, then reclaimable desc
    proposals.sort(key=lambda p: ({"low":0,"medium":1,"high":2}[p["risk"]], -p["reclaimable_bytes"]))
    return proposals
