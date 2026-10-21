#!/usr/bin/env python3
"""Cross-check 7.1 Lv3 chest client IDs against two public resource copies.

The four unmodified input JSON files are checked by Git blob SHA-1. The
independently authenticated Gadget identities come from a pinned report.
This proves public-copy agreement, not original client ownership or rewards.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"
BLOBS = {
    "cn_audio": "f2f2f9c05e6333a9dc302b11a1bc39e16f621f5f",
    "server_audio": "e1d44e330366a4d7c8bd1a88dc9bb9f5576dad52",
    "cn_investigation": "ce68e53c43a3f014ea836604917d9db976c1ec87",
    "server_investigation": "795eab6cd624b36cea0ad47ac5e9055e2f8765f8",
}
NATIVE_SHA = "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
STYLES = ("Default", "Locked", "Bramble", "Frozen")
AUDIO_ID = "AIMCCDKDAKB"
AUDIO_CLASS = "DMNAJDGMHDE"
EXPECTED_AUDIO_ROWS = 56
EXPECTED_INVESTIGATION_ROWS = 252
EXPECTED_TRIGGER_IDS = 88


def pinned_json(path: Path, expected_blob: str):
    raw = path.read_bytes()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\\0" + raw).hexdigest()
    if digest != expected_blob:
        raise ValueError(f"public source-copy Git blob mismatch: {path}")
    return json.loads(raw)


def audio_index(rows: list[dict]) -> dict[int, str | None]:
    result: dict[int, str | None] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) - {AUDIO_ID, AUDIO_CLASS}:
            raise ValueError("unexpected audio classification schema")
        gid = row.get(AUDIO_ID)
        if type(gid) is not int or gid in result:
            raise ValueError("missing/duplicate audio gadget ID")
        label = row.get(AUDIO_CLASS)
        if label is not None and label not in ("Mid", "Hi", "Top"):
            raise ValueError("unexpected audio classification label")
        result[gid] = label
    return result


def chest_open_trigger(rows: list[dict]) -> tuple[int, ...]:
    matches = [row for row in rows if row.get("id") == 60003]
    if len(matches) != 1:
        raise ValueError("missing or duplicate handbook chest-open target")
    row = matches[0]
    if row.get("questId") != 6000003 or row.get("investigationId") != 10001:
        raise ValueError("handbook chest target metadata changed")
    cfg = row["triggerConfig"]
    if cfg.get("triggerType") != "TRIGGER_OPEN_CHEST_WITH_GADGET_ID":
        raise ValueError("handbook target is not a chest-open trigger")
    params = cfg.get("paramList")
    if not isinstance(params, list) or len(params) != 3 or params[1:] != ["", ""]:
        raise ValueError("unexpected chest-open trigger parameters")
    words = params[0].split(";")
    if not words or any(not w.isascii() or not w.isdecimal() for w in words):
        raise ValueError("invalid gadget ID text in chest-open trigger")
    ids = tuple(map(int, words))
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ID in chest-open trigger")
    return ids


def audit(native: dict, cn_audio: list, server_audio: list,
          cn_investigation: list, server_investigation: list) -> dict:
    if (native.get("source", {}).get("rawExportSha256") != NATIVE_SHA
            or native.get("controls", {}).get("verifiedGadgetDefinitionCount") != 20):
        raise ValueError("original 7.1 Gadget controls are not the pinned source")
    if len(cn_audio) != EXPECTED_AUDIO_ROWS or len(server_audio) != EXPECTED_AUDIO_ROWS:
        raise ValueError("unexpected audio source row count")
    if (len(cn_investigation) != EXPECTED_INVESTIGATION_ROWS
            or len(server_investigation) != EXPECTED_INVESTIGATION_ROWS):
        raise ValueError("unexpected investigation source row count")
    a, b = audio_index(cn_audio), audio_index(server_audio)
    if a != b:
        raise ValueError("audio gadget classification differs across public copies")
    ids_cn = chest_open_trigger(cn_investigation)
    ids_server = chest_open_trigger(server_investigation)
    if ids_cn != ids_server or len(ids_cn) != EXPECTED_TRIGGER_IDS:
        raise ValueError("handbook chest-open ID list differs across public copies")
    trigger_set = set(ids_cn)
    names = native["controls"]["nativeNameFields"]
    if len(names) != 20:
        raise ValueError("unexpected pinned native chest control length")
    core = []
    for level in range(1, 6):
        for variant, style in enumerate(STYLES, 1):
            gid = 70210000 + 10 * level + variant
            found = [row for row in names if row["gadgetIdPreWrapperScalar"] == gid]
            if len(found) != 1 or found[0]["nativeNameString"] != f"SceneObj_Chest_{style}_Lv{level}":
                raise ValueError(f"mismatched source-pinned Gadget ID/name: {gid}")
            if gid not in a or gid not in trigger_set:
                raise ValueError(f"native Gadget missing from corroborating client copy: {gid}")
            expected_label = {1: None, 2: None, 3: "Mid", 4: "Hi", 5: "Top"}[level]
            if a[gid] != expected_label:
                raise ValueError(f"native Gadget audio classification changed: {gid}")
            core.append({"gadgetIdPreWrapperScalar": gid, "nameSuffix": level,
                         "style": style, "audioClass": a[gid],
                         "inHandbookChestOpenTrigger": True})
    return {
        "schemaVersion": 1,
        "status": "CN_71_AND_SERVER_COPY_CLIENT_SEMANTIC_AGREEMENT__ORIGINAL_71_LV3_REWARD_UNVERIFIED",
        "originalNativeGadgetRawSha256": NATIVE_SHA,
        "publicCopyGitBlobs": BLOBS,
        "crossSourceAudioRows": len(a),
        "crossSourceChestOpenTriggerIds": len(ids_cn),
        "coreClientDefinitionsCrossChecked": len(core),
        "nativeCoreSuffixAudioClasses": [
            {"literalNameSuffix": level,
             "classes": dict(Counter(item["audioClass"] or "(absent)"
                         for item in core if item["nameSuffix"] == level))}
            for level in range(1, 6)
        ],
        "lv3ClientGadgetIdsInChestOpenTrigger": [
            item["gadgetIdPreWrapperScalar"] for item in core if item["nameSuffix"] == 3
        ],
        "limitations": [
            "CN community and server-resource copies may share an ancestor; their agreement is not independent extraction authentication.",
            "The native 20 Gadget definitions are authenticated separately from the two public JSON tables.",
            "Audio Mid/Hi/Top labels describe audio configuration; no server payable grade follows.",
            "The handbook trigger lists supported gadget IDs but proves no scene/group/config placement or actual opening.",
            "Neither public copy proves original 7.1 reward roots, values, drop_tag or probabilities.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cn-audio", required=True, type=Path)
    p.add_argument("--server-audio", required=True, type=Path)
    p.add_argument("--cn-investigation", required=True, type=Path)
    p.add_argument("--server-investigation", required=True, type=Path)
    p.add_argument("--native", type=Path, default=NATIVE)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    files = {
        "cn_audio": a.cn_audio, "server_audio": a.server_audio,
        "cn_investigation": a.cn_investigation,
        "server_investigation": a.server_investigation,
    }
    raw = {name: pinned_json(path, BLOBS[name]) for name, path in files.items()}
    report = audit(json.loads(a.native.read_text(encoding="utf-8")),
                   raw["cn_audio"], raw["server_audio"],
                   raw["cn_investigation"], raw["server_investigation"])
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
