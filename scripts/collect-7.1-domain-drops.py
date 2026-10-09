#!/usr/bin/env python3
"""Collect pinned 7.1 Dungeon drop graphs and weekday references."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from genshinre.dungeondrops import collect_dungeon_drop_links

OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-domain-drop-links.json"
COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
BLOBS = {
    "ExcelBinOutput/DungeonExcelConfigData.json": "92983c5d9d46bccf486b803b7cf65f2cdf9088cb",
    "Server/DropTableExcelConfigData.json": "b46d383b535babd1be6b95e3ea031eef64d1fdfd",
    "Server/DropSubTableExcelConfigData.json": "9397fb0b15c8c4cc82194ec429682f2ef4333767",
    "ExcelBinOutput/DailyDungeonConfigData.json": "df450f5daeb484e94840af7e207f20cdde8cedbd",
}


def build_snapshot(resource_root: Path) -> dict:
    rows, evidence = {}, {}
    for filename, expected in BLOBS.items():
        raw = (resource_root / filename).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: Git blob SHA {actual} != {expected}")
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"{filename}: expected JSON array")
        rows[filename] = data
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(data)}
    result = collect_dungeon_drop_links(*(rows[name] for name in BLOBS))
    tool_blobs = {}
    for path in ("scripts/collect-7.1-domain-drops.py", "genshinre/dungeondrops.py"):
        raw = (ROOT / path).read_bytes()
        tool_blobs[path] = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    return {
        "schemaVersion": 1, "target": "Genshin Impact 7.1.0 Global",
        "scope": "source-row joins only; no runtime/probability assertion; weekday membership does not prove enforcement; terminal IDs are not verified inventory items",
        "source": {"repository": "RinoPaw/AstaPS-Resource", "commit": COMMIT, "files": evidence},
        "generator": {"script": "scripts/collect-7.1-domain-drops.py", "module": "genshinre.dungeondrops",
                      "toolGitBlobShas": tool_blobs,
                      "command": "python scripts/collect-7.1-domain-drops.py --resource-root /path/to/AstaPS-Resource --check"},
        **result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = build_snapshot(args.resource_root)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("Dungeon source joins differ from snapshot")
        print("PASS: pinned 7.1 Dungeon drop graphs and schedule references")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
