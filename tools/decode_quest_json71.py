from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

TOP_LEVEL = {
    "DOOCLIPFECE": "titleTextMapHash",
    "JIJKODHIEED": "subQuests",
    "JNHHOJAPDPP": "preloadLuaList",
    "NBOJMAHCCGM": "descTextMapHash",
}

SUB_QUEST = {
    "MDLABCMFLMH": "showGuide",
    "HINHMGGLBBM": "guide",
    "NFGFDHPPBIF": "subId",
    "NBOJMAHCCGM": "descTextMapHash",
    "GBFIFKGFKHD": "order",
    "KGNKIMLCNMC": "isRewind",
    "MIABAAMCOFK": "finishParent",
    "PCOMHEOJPOO": "mainId",
    "FAPCNCGCEBJ": "finishExec",
    "KHEBAEMAPPJ": "failCond",
    "CNPOFCKIBDL": "failExec",
    "BIHKOLLEDPE": "guideHint",
    "HEMLAEELDFC": "isMpBlock",
    "IILNPFILEGJ": "subIdSet",
    "JFCJBBCEDGD": "sharedNpcList",
    "FKKAEBOAMCN": "stepDescTextMapHash",
    "KBDPGMJFJGO": "guideTipsTextMapHash",
    "KIILAIEPKIA": "banType",
}

COND = {
    "JBELGECAIIL": "param_str",
}

GUIDE = {
    "IEOAOICBOLJ": "guideScene",
    "NAPKNCOFMKI": "guideStyle",
    "DANOJMJOHPI": "guideLayer",
    "PHOCDKAEENN": "autoGuide",
    "FPMPILEAIOL": "poiPointId",
    "GJCMGJEFAGF": "poiRegionId",
    "AMCLBMAOELH": "inSceneStyle",
    "NJGODCNNNNJ": "indicatorStyle",
    "ABIJICNCCOD": "areaStyle",
}

KNOWN_TOP = {
    "id", "rewardIdList", "luaPath", "suggestTrackMainQuestList", "series",
    "resId", "titleTextMapHash", "descTextMapHash", "subQuests",
    "preloadLuaList",
}
KNOWN_SUB = {
    "subId", "mainId", "order", "descTextMapHash", "showType", "showGuide",
    "guide", "isRewind", "finishParent", "finishCond", "failCond",
    "finishExec", "failExec", "acceptCond", "beginExec", "finishCondComb",
    "failCondComb", "acceptCondComb", "guideHint", "isMpBlock", "subIdSet",
    "sharedNpcList", "stepDescTextMapHash", "guideTipsTextMapHash", "banType",
}
KNOWN_COND = {"type", "param", "param_str", "count"}
KNOWN_GUIDE = {
    "type", "param", "guideScene", "guideStyle", "guideLayer", "autoGuide",
    "poiPointId", "poiRegionId", "inSceneStyle", "indicatorStyle", "areaStyle",
}


def _rename(obj: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in obj.items():
        new_key = mapping.get(key, key)
        if new_key in out and new_key != key:
            raise ValueError(f"field collision: {key!r} -> {new_key!r}")
        out[new_key] = value
    return out


def _decode_cond_list(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    out = []
    for item in value:
        out.append(_rename(item, COND) if isinstance(item, dict) else item)
    return out


def _decode_exec_list(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    out = []
    for item in value:
        out.append(_rename(item, COND) if isinstance(item, dict) else item)
    return out


def _decode_guide(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return _rename(value, GUIDE)


def decode_quest(obj: dict[str, Any]) -> dict[str, Any]:
    out = _rename(obj, TOP_LEVEL)
    subs = out.get("subQuests")
    if isinstance(subs, list):
        decoded = []
        for item in subs:
            if not isinstance(item, dict):
                decoded.append(item)
                continue
            row = _rename(item, SUB_QUEST)
            for field in ("acceptCond", "finishCond", "failCond"):
                if field in row:
                    row[field] = _decode_cond_list(row[field])
            for field in ("beginExec", "finishExec", "failExec"):
                if field in row:
                    row[field] = _decode_exec_list(row[field])
            if "guide" in row:
                row["guide"] = _decode_guide(row["guide"])
            decoded.append(row)
        out["subQuests"] = decoded
    return out


def _collect_unknown(report: Counter[str], obj: dict[str, Any]) -> None:
    for key in obj:
        if key not in KNOWN_TOP:
            report[f"top.{key}"] += 1
    subs = obj.get("subQuests")
    if not isinstance(subs, list):
        return
    for row in subs:
        if not isinstance(row, dict):
            continue
        for key in row:
            if key not in KNOWN_SUB:
                report[f"sub.{key}"] += 1
        for field in ("acceptCond", "finishCond", "failCond", "beginExec", "finishExec", "failExec"):
            seq = row.get(field)
            if not isinstance(seq, list):
                continue
            for item in seq:
                if isinstance(item, dict):
                    for key in item:
                        if key not in KNOWN_COND:
                            report[f"{field}.{key}"] += 1
        guide = row.get("guide")
        if isinstance(guide, dict):
            for key in guide:
                if key not in KNOWN_GUIDE:
                    report[f"guide.{key}"] += 1


def decode_directory(source: Path, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    unknown: Counter[str] = Counter()
    files = 0
    subquests = 0
    for path in sorted(source.glob("*.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            continue
        decoded = decode_quest(obj)
        _collect_unknown(unknown, decoded)
        subs = decoded.get("subQuests")
        if isinstance(subs, list):
            subquests += len(subs)
        (output / path.name).write_text(
            json.dumps(decoded, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        files += 1
    return {
        "quest_files": files,
        "subquests": subquests,
        "unknown_fields": dict(sorted(unknown.items())),
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Decode Genshin 7.1 BinOutput/Quest JSON field names.")
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--report", type=Path)
    args = p.parse_args()
    report = decode_directory(args.source, args.output)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
