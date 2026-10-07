#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.questbin import parse_main_quest


def _coverage_index(coverage: dict) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for row in coverage.get("quests", []):
        hint = row.get("mainIdHint")
        if hint is None:
            continue
        out[int(hint)] = row
    return out


def export_native_quests(
    payload_dir: Path,
    coverage_path: Path,
    output_path: Path,
    *,
    decoder_commit: str | None,
) -> dict:
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage_rows = _coverage_index(coverage)

    main_quests: list[dict] = []
    failed_main_quests: list[dict] = []

    for main_id in sorted(coverage_rows):
        row = coverage_rows[main_id]
        payload = payload_dir / str(main_id)
        if row.get("status") != "full":
            failed_main_quests.append(
                {
                    "mainId": main_id,
                    "size": int(row.get("size", 0)),
                    "failureFamilies": list(row.get("failureFamilies", [])),
                    "error": row.get("error"),
                }
            )
            continue

        raw = payload.read_bytes()
        quest = parse_main_quest(raw)
        if not quest.fully_consumed:
            raise RuntimeError(
                f"coverage says full but parser consumed {quest.consumed}/{quest.size} for {main_id}"
            )
        if quest.main_id is not None and quest.main_id != main_id:
            raise RuntimeError(
                f"payload {main_id} decoded as mainId {quest.main_id}"
            )

        item = quest.to_dict()
        item["mainId"] = main_id
        item["payloadSize"] = len(raw)
        item["payloadSha256"] = hashlib.sha256(raw).hexdigest()
        main_quests.append(item)

    if len(main_quests) != int(coverage["fullConsumed"]):
        raise RuntimeError(
            f"exported {len(main_quests)} full quests, coverage reports {coverage['fullConsumed']}"
        )
    if len(main_quests) + len(failed_main_quests) != int(coverage["total"]):
        raise RuntimeError("exported quest count does not match coverage total")

    result = {
        "schemaVersion": 1,
        "gameVersion": "7.1.0-global",
        "source": {
            "repository": "RinoPaw/Genshin-Reverse",
            "decoder": "native Quest BinOutput",
            "decoderCommit": decoder_commit,
            "policy": "Only fully consumed native payloads appear in mainQuests; failed payloads remain diagnostic-only.",
        },
        "coverage": {
            "total": int(coverage["total"]),
            "fullConsumed": int(coverage["fullConsumed"]),
            "failed": int(coverage["failed"]),
            "payloadBytes": int(coverage["payloadBytes"]),
            "failureFamilies": coverage.get("failureFamilies", []),
        },
        "mainQuests": main_quests,
        "failedMainQuests": failed_main_quests,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export a reproducible native 7.1 quests.json from exact payloads."
    )
    parser.add_argument("payload_dir", type=Path)
    parser.add_argument("coverage", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--decoder-commit")
    args = parser.parse_args()

    result = export_native_quests(
        args.payload_dir,
        args.coverage,
        args.output,
        decoder_commit=args.decoder_commit,
    )
    print(
        json.dumps(
            {
                "total": result["coverage"]["total"],
                "fullConsumed": result["coverage"]["fullConsumed"],
                "failed": result["coverage"]["failed"],
                "output": str(args.output),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
