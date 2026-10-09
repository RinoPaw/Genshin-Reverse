#!/usr/bin/env python3
"""Exact-sample, non-promoting 7.1 Amber pause-request investigation.

All semantic hypotheses remain outside known-opcodes.csv.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.rowutil import parse_optional_int


REQUEST_CMD = 5963
HISTORICAL_RESPONSE_CMD = 2870


def load_csv(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        yield from csv.DictReader(stream)


def locate_command(rows: list[dict[str, str]], command: int) -> dict[str, str] | None:
    matches = [row for row in rows if parse_optional_int(row.get("cmd_id")) == command]
    if len(matches) > 1:
        raise ValueError(f"duplicate canonical CmdId {command}")
    return matches[0] if matches else None


def method_references(rows: list[dict[str, str]], type_name: str) -> list[dict[str, str]]:
    # Preserve exact token boundaries: "AXYZ" must not match type "XYZ".
    from genshinre.metadatacsv import parse_parameter_types

    found = []
    for row in rows:
        params = parse_parameter_types(row.get("parameter_types", ""))
        if type_name in params or str(row.get("return_type", "")).strip() == type_name:
            found.append(row)
    return found


def summary_rows(rows: list[dict[str, str]], limit: int = 50) -> dict:
    return {"count": len(rows), "rows": rows[:limit], "truncated": len(rows) > limit}


def investigate(version: Path, exe: Path | None = None) -> dict:
    registry = list(load_csv(version / "registry" / "registry.csv"))
    req = locate_command(registry, REQUEST_CMD)
    if req is None:
        raise ValueError(f"CmdId {REQUEST_CMD} absent from canonical 7.1 registry")
    req_type = req["type_name"]
    methods_path = version / "metadata" / "methods.csv"
    methods = list(load_csv(methods_path))
    fields_path = version / "metadata" / "fields.csv"
    req_fields = [
        row for row in load_csv(fields_path)
        if parse_optional_int(row.get("type_definition_index"))
        == parse_optional_int(req.get("type_definition_index"))
    ]
    old_rsp = locate_command(registry, HISTORICAL_RESPONSE_CMD)
    old_rsp_fields = [row for row in load_csv(fields_path)
                      if old_rsp is not None and parse_optional_int(row.get("type_definition_index"))
                      == parse_optional_int(old_rsp.get("type_definition_index"))]
    own_methods = [row for row in methods if row.get("type_name") == req_type]
    external_refs = [
        row for row in method_references(methods, req_type)
        if row.get("type_name") != req_type
    ]
    receiver_type = "LLCGIEDMIIG"
    receiver_methods = [row for row in methods if row.get("type_name") == receiver_type]
    receiver_registry_refs = {}
    registry_by_type = {row["type_name"]: row for row in registry}
    for method in receiver_methods:
        from genshinre.metadatacsv import parse_parameter_types
        for param in parse_parameter_types(method.get("parameter_types", "")):
            if param in registry_by_type:
                rid = registry_by_type[param]["cmd_id"]
                receiver_registry_refs.setdefault(rid, []).append({
                    "method_name": method.get("method_name"),
                    "rva": method.get("rva"),
                    "parameter_type": param
                })
    result = {
        "status": "STATIC_RECONNAISSANCE_ONLY",
        "sample": {"identity": PROFILE_71.identity, "exe_sha256": PROFILE_71.exe_sha256,
                   "metadata_sha256": PROFILE_71.metadata_sha256},
        "anchors": {"request_cmd_id": REQUEST_CMD, "historical_response_cmd_id": HISTORICAL_RESPONSE_CMD,
                    "historical_response_not_current_evidence": True},
        "request_registry": req,
        "historical_response_registry_row_not_semantic": old_rsp,
        "historical_response_fields_not_semantic": old_rsp_fields,
        "request_fields": req_fields,
        "request_methods": summary_rows(own_methods, 75),
        "request_external_signature_refs": summary_rows(external_refs, 75),
        "request_external_declaring_types": Counter(
            row.get("type_name", "") for row in external_refs
        ).most_common(50),
        "receiver_owner": receiver_type,
        "receiver_method_count": len(receiver_methods),
        "receiver_registry_param_count": len(receiver_registry_refs),
        "receiver_known_protocol_control": {
            key: receiver_registry_refs.get(str(key), []) for key in (2870, 4385, 7003, 22060)
        },
        "evidence_limits": [
            "Canonical CmdId-to-type identity is not a semantic mapping.",
            "Method signatures and slot references alone cannot confirm PlayerSetPauseRsp.",
            "No Amber input-lock causal claim follows from static reconstruction."
        ]
    }
    if exe is not None:
        from genshinre.sampleidentity import require_profile_exe
        from genshinre.xrefs import scan_rip_xrefs
        result["verified_exe_sha256"] = require_profile_exe(exe, PROFILE_71)
        slot = parse_optional_int(req["type_slot_rva"])
        if slot is None:
            raise ValueError("request registry has no type slot")
        old_slot = parse_optional_int(old_rsp["type_slot_rva"]) if old_rsp else None
        slots = [slot] + ([old_slot] if old_slot is not None else [])
        refs = scan_rip_xrefs(exe, slots, methods_csv=methods_path, window=48)
        result["request_type_slot_xrefs"] = refs["matches"].get(f"0x{slot:X}", [])
        result["request_type_slot_xref_count"] = len(result["request_type_slot_xrefs"])
        if old_slot is not None:
            result["historical_response_type_slot_xrefs_not_semantic"] = refs["matches"].get(f"0x{old_slot:X}", [])
        sender_methods = []
        for hit in result["request_type_slot_xrefs"]:
            for method in hit.get("caller_methods", []):
                if method.get("type_name") != req_type and method.get("type_name") != "FBGCJGDKLLB":
                    sender_methods.append(method)
        unique_senders = {method["rva"]: method for method in sender_methods if method.get("rva")}
        if unique_senders:
            from genshinre.callxref import scan_direct_call_xrefs
            from tools.disassemble_rva import disassemble_rva
            sender_rvas = [int(value, 0) for value in unique_senders]
            call_refs = scan_direct_call_xrefs(
                exe, sender_rvas, methods_csv=methods_path, window=64
            )
            result["request_sender_methods"] = list(unique_senders.values())
            result["request_sender_call_xrefs"] = call_refs["matches"]
            result["request_sender_native_disassembly"] = {
                rva: disassemble_rva(exe, int(rva, 0), 0x90)["instructions"]
                for rva in unique_senders
            }
            caller_methods = {}
            for group in call_refs["matches"].values():
                for hit in group:
                    for method in hit.get("caller_methods", []):
                        if method.get("rva"):
                            caller_methods[method["rva"]] = method
            result["request_sender_callers"] = list(caller_methods.values())
            result["request_sender_caller_disassembly"] = {
                rva: disassemble_rva(exe, int(rva, 0), 0x220)["instructions"]
                for rva in caller_methods
            }
            result["request_parser_disassembly"] = disassemble_rva(
                exe, 0xA580610, 0x130
            )["instructions"]
            caller_param_types = set()
            from genshinre.metadatacsv import parse_parameter_types
            for method in caller_methods.values():
                caller_param_types.update(parse_parameter_types(method.get("parameter_types", "")))
            result["caller_input_registry"] = [
                registry_by_type[name] for name in sorted(caller_param_types)
                if name in registry_by_type
            ]
            result["caller_input_fields"] = [
                field for field in load_csv(fields_path)
                if field.get("type_name") in caller_param_types
            ]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", type=Path, default=Path("versions/7.1.0-global/windows-x64"))
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = investigate(args.version, args.exe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "request_registry": report["request_registry"],
        "request_external_declaring_types": report["request_external_declaring_types"],
        "request_type_slot_xref_count": report.get("request_type_slot_xref_count"),
        "receiver_method_count": report["receiver_method_count"]
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
