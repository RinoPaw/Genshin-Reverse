#!/usr/bin/env python3
"""Pin and rebuild the AstaPS talent-domain proxy (B, not native 7.1 rates)."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

BASE = (Path(__file__).resolve().parents[1] /
        "versions/7.1.0-global/analyses/progression/economy")
LINKS = BASE / "7.1-talent-domain-drop-links.json"
OUTPUT = BASE / "7.1-talent-domain-server-proxy.json"
COMMIT = "b1c5af21a26deaaa9983f485d98cd32e5693e64e"
BLOB = "7fdd3b01d7b4fedc5837eae776502aeffc2fe3ed"


def build_snapshot(native: dict, path: Path) -> dict:
    if native["source"]["repository"] != "RinoPaw/AstaPS-Resource":
        raise ValueError("unexpected resource origin")
    if native["summary"]["talentDungeonRows"] != 104:
        raise ValueError("unexpected source dungeon coverage")
    raw = path.read_bytes()
    digest = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    if digest != BLOB:
        raise ValueError(f"DungeonDrop.json Git blob SHA mismatch: {digest}")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("expected DungeonDrop array")
    by_id = {x["dungeonId"]: x for x in data}
    if len(by_id) != len(data):
        raise ValueError("duplicate dungeonId")
    domains = sorted(native["domains"], key=lambda x: x["dungeonId"])
    selected = []
    for x in domains:
        if x["dungeonId"] not in by_id:
            continue
        row = by_id[x["dungeonId"]]
        out = {"dungeonId": row["dungeonId"]}
        if "comment" in row:
            out["comment"] = row["comment"]
        out["drops"] = row["drops"]
        selected.append(out)
    both = sum(x["rootPresent"] for x in domains
               if x["dungeonId"] in by_id)
    summary = {
        "talentDungeonCount": len(domains),
        "serverProxyRows": len(selected),
        "withoutServerProxy": [x["dungeonId"] for x in domains
                               if x["dungeonId"] not in by_id],
        "serverOnlyRows": len(selected) - both,
        "withNativeRootAndProxy": both,
    }
    if (len(data), len(domains), len(selected), both) != (266, 104, 96, 48):
        raise ValueError("pinned server proxy coverage differs")
    return {
        "schemaVersion": 1,
        "target": "AstaPS server-side proxy for 7.1 talent dungeons",
        "evidence": "B: private-server implementation, NOT 7.1 native drop probability evidence",
        "source": {
            "repository": "RinoPaw/AstaPS",
            "commit": COMMIT,
            "path": "data/DungeonDrop.json",
            "gitBlobSha": BLOB,
            "wholeFileRowCount": len(data),
        },
        "summary": summary,
        "dungeons": selected,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server-drops", type=Path, required=True)
    p.add_argument("--source-snapshot", type=Path, default=LINKS)
    p.add_argument("--output", type=Path, default=OUTPUT)
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    native = json.loads(a.source_snapshot.read_text(encoding="utf-8"))
    result = build_snapshot(native, a.server_drops)
    if a.check:
        if json.loads(a.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("AstaPS proxy snapshot differs from pinned input")
        print("PASS: pinned AstaPS talent-domain proxy")
    else:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(f"Wrote {a.output}")


if __name__ == "__main__":
    main()
