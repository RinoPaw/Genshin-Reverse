#!/usr/bin/env python3
"""Exact 7.1 WorldArea request native producer probe.

Starts at registry-backed CmdId 25407 / type GEAMLDNCCEP and tests
validated x86-64 direct callers. No semantic promotion is automatic.
Requires an exact pinned executable and metadata sample.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.pointerxref import scan_pointer_xrefs
from genshinre.xrefs import scan_rip_xrefs
from genshinre.sampleidentity import require_profile_exe, require_profile_metadata

REQUEST = (25407, "GEAMLDNCCEP", 82921)
RESPONSE = (6774, "ICMCPHPFIKJ", 83231)
CANDIDATE_TYPES = ("KLLNGCPBLMM", "HJJINELFFMJ", "EOFNANCNGFK", "CEBMPFCJPGE")


def matching_signature(value: str, name: str) -> bool:
    """Recognize one exact type token, including metadata JSON arrays."""
    if not value:
        return False
    try:
        tokens = json.loads(value)
        if isinstance(tokens, list):
            return name in tokens
    except (ValueError, TypeError):
        pass
    # A return type may be a naked token or a generic with token delimiters.
    import re
    return bool(re.search(r"(?<![A-Za-z0-9_])" + re.escape(name)
                          + r"(?![A-Za-z0-9_])", value))


def load_registry(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = {int(row["cmd_id"]): row for row in csv.DictReader(stream)}
    anchors = []
    for cmd, name, definition in (REQUEST, RESPONSE):
        row = rows[cmd]
        if (row["type_name"] != name
                or int(row["type_definition_index"]) != definition):
            raise ValueError(f"unexpected 7.1 CmdId {cmd} identity: {row}")
        anchors.append({
            "cmd_id": cmd,
            "type_name": name,
            "type_definition_index": definition,
            "get_cmd_id_rva": row.get("get_cmd_id_rva"),
            "type_slot_rva": row.get("type_slot_rva"),
            "registry_status": row.get("status"),
            "semantic_source": "AstaPS PacketOpcodes; 7.1 registry holds only numeric identity",
        })
    return anchors


def stream_metadata(methods: Path, fields: Path) -> dict[str, object]:
    type_ids = {REQUEST[2], RESPONSE[2]}
    type_names = {REQUEST[1], RESPONSE[1]}
    method_rows: dict[str, list[dict[str, str]]] = {name: [] for name in type_names}
    candidate_methods: dict[str, list[dict[str, str]]] = {name: [] for name in CANDIDATE_TYPES}
    external: list[dict[str, object]] = []
    with methods.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                idx = int(row["type_definition_index"], 0)
            except (ValueError, KeyError):
                continue
            if idx in type_ids:
                method_rows[row["type_name"]].append(row)
            if row.get("type_name") in candidate_methods:
                candidate_methods[row["type_name"]].append({k: row.get(k, "") for k in (
                    "method_index", "method_name", "type_definition_index", "rva",
                    "parameter_types", "return_type")})
            elif any(matching_signature(row.get("parameter_types", ""), name)
                     or matching_signature(row.get("return_type", ""), name)
                     for name in type_names):
                external.append({
                    key: row.get(key, "")
                    for key in ("method_index", "type_name", "type_definition_index",
                                "method_name", "rva", "return_type", "parameter_types")
                })
    field_rows: dict[str, list[dict[str, str]]] = {name: [] for name in type_names}
    candidate_fields: dict[str, list[dict[str, str]]] = {name: [] for name in CANDIDATE_TYPES}
    with fields.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                idx = int(row["type_definition_index"], 0)
            except (ValueError, KeyError):
                continue
            if idx in type_ids:
                field_rows[row["type_name"]].append(row)
            if row.get("type_name") in candidate_fields:
                candidate_fields[row["type_name"]].append({k: row.get(k, "") for k in (
                    "field_index", "field_name", "type_definition_index", "field_type")})
    if not method_rows[REQUEST[1]] or not method_rows[RESPONSE[1]]:
        raise ValueError("missing exact sample area protocol method rows")
    return {
        "protocol_methods": method_rows,
        "protocol_fields": field_rows,
        "external_signature_references": external,
        "candidate_owner_methods": candidate_methods,
        "candidate_owner_fields": candidate_fields,
    }


def brief_caller(row: dict[str, str]) -> dict[str, str]:
    return {key: row.get(key, "") for key in (
        "method_index", "type_name", "type_definition_index",
        "method_name", "rva", "parameter_count", "parameter_types",
    )}


def valid_direct_calls(exe: Path, methods_csv: Path,
                       targets: list[int]) -> dict[str, object]:
    """Validate candidate E8 hits against containing method disassembly.

    A byte equal to E8 inside data or an immediate is not enough evidence.
    Keep duplicate declaring-method owners explicit.
    """
    if not targets:
        return {"targets": [], "validated": {}, "rejected_candidates": 0}
    raw = scan_direct_call_xrefs(exe, targets, methods_csv=methods_csv, window=10)
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    accepted = {}
    rejected = 0
    with PEImage(exe) as image:
        image_base = image.image_base
        cached = {}
        for label, rows in raw["matches"].items():
            out = []
            for row in rows:
                site = int(row["instruction_rva"], 0)
                owners = row.get("caller_methods") or []
                good_owners = []
                for owner in owners:
                    try:
                        start = int(owner["rva"], 0)
                    except (KeyError, ValueError):
                        continue
                    if not (start <= site < start + 0x10000):
                        continue
                    # Disassemble only to the candidate site; no method-size guess
                    # can establish the next method boundary for this check.
                    max_end = min(0x10000, site - start + 16)
                    previous = cached.get(start)
                    if previous is None or previous[0] < max_end:
                        cached[start] = (
                            max_end,
                            list(md.disasm(image.read_rva(start, max_end),
                                           image_base + start)),
                        )
                    insns = cached[start][1]
                    if any((ins.address - image_base == site
                            and ins.mnemonic == "call"
                            and ins.bytes.hex() == row["instruction_hex"])
                           for ins in insns):
                        good_owners.append(brief_caller(owner))
                if not good_owners:
                    rejected += 1
                    continue
                out.append({
                    "site_rva": row["instruction_rva"],
                    "call_bytes": row["instruction_hex"],
                    "target_rva": row["target_rva"],
                    "callers": good_owners,
                })
            accepted[label] = out
    return {
        "targets": [f"0x{x:X}" for x in targets],
        "validated": accepted,
        "rejected_candidates": rejected,
        "limits": [
            "Only E8 rel32 direct calls are found; virtual, indirect, and inlined construction remain unresolved",
            "Caller ownership comes from nearest metadata RVA and may be ambiguous where the client shares method bodies",
        ],
    }


def probe(exe: Path, metadata: Path, methods: Path, fields: Path,
          registry: Path) -> dict[str, object]:
    exe_hash = require_profile_exe(exe, PROFILE_71)
    metadata_hash = require_profile_metadata(metadata, PROFILE_71)
    anchors = load_registry(registry)
    indexed = stream_metadata(methods, fields)
    req = indexed["protocol_methods"][REQUEST[1]]
    target_methods = {}
    for row in req:
        try:
            rva = int(row.get("rva") or "0", 0)
        except ValueError:
            continue
        if rva > 0:
            target_methods[f"0x{rva:X}"] = brief_caller(row)
    calls = valid_direct_calls(exe, methods, sorted(int(x, 0) for x in target_methods))
    # Run one additional independent hop for a small bounded set of caller RVAs.
    first_callers = {}
    for rows in calls["validated"].values():
        for hit in rows:
            for caller in hit["callers"]:
                try:
                    rva = int(caller["rva"], 0)
                except ValueError:
                    continue
                if rva > 0 and caller["type_name"] != REQUEST[1]:
                    first_callers[rva] = caller
    second_targets = sorted(first_callers)[:32]
    caller_calls = valid_direct_calls(exe, methods, second_targets) if second_targets else None
    slot_rvas = [int(a["type_slot_rva"], 0) for a in anchors]
    slot_xrefs = scan_rip_xrefs(exe, slot_rvas, window=12,
                               methods_csv=methods)
    # The request method RVA range is deliberately bounded to the eight
    # declared request methods; pointer holders are separate evidence
    # from E8 direct callers.
    req_rvas = sorted(int(x, 0) for x in target_methods)
    pointer_xrefs = scan_pointer_xrefs(exe, req_rvas[0],
                                      req_rvas[-1] + 0x20, window=12)
    return {
        "status": "NATIVE_DIRECT_CALL_EVIDENCE_ONLY__AREA_SELECTION_UNRESOLVED",
        "sample": "7.1.0-global/windows-x64",
        "exe_sha256": exe_hash,
        "metadata_sha256": metadata_hash,
        "registry_anchors": anchors,
        "metadata": indexed,
        "target_methods_by_rva": target_methods,
        "request_method_direct_calls": calls,
        "first_hop_external_caller_count": len(first_callers),
        "second_hop_target_count": len(second_targets),
        "second_hop_direct_calls": caller_calls,
        "registry_slot_code_xrefs": slot_xrefs,
        "request_method_pointer_holders": pointer_xrefs,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--metadata", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--fields", type=Path, required=True)
    p.add_argument("--registry", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    report = probe(args.exe, args.metadata, args.methods, args.fields, args.registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("WORLD_AREA_NATIVE_SUMMARY_BEGIN", flush=True)
    print(json.dumps({
        "sample": report["sample"],
        "anchors": report["registry_anchors"],
        "request_methods": [
            {"rva": rva, "name": info["method_name"],
             "parameter_types": info["parameter_types"]}
            for rva, info in report["target_methods_by_rva"].items()
        ],
        "protocol_fields": report["metadata"]["protocol_fields"],
        "candidate_owner_methods": {k: v[:50] for k, v in report["metadata"]["candidate_owner_methods"].items()},
        "candidate_owner_method_counts": {k: len(v) for k, v in report["metadata"]["candidate_owner_methods"].items()},
        "candidate_owner_fields": report["metadata"]["candidate_owner_fields"],
        "external_signature_references": report["metadata"]["external_signature_references"][:50],
        "external_signature_reference_count": len(report["metadata"]["external_signature_references"]),
        "direct_callers": report["request_method_direct_calls"]["validated"],
        "first_hop_external_caller_count": report["first_hop_external_caller_count"],
        "second_hop_direct_calls": (report["second_hop_direct_calls"] or {}).get("validated", {}),
        "registry_slot_code_xrefs": {
            k: [{
                "site_rva": row["instruction_rva"],
                "insn_hex": row["instruction_hex"],
                "candidate_callers": [brief_caller(q) for q in row.get("caller_methods", [])][:5],
            } for row in value[:40]]
            for k, value in report["registry_slot_code_xrefs"]["matches"].items()
        },
        "method_pointer_holder_count": report["request_method_pointer_holders"]["holder_count"],
        "method_pointer_holders_with_code_xrefs": report["request_method_pointer_holders"]["holders_with_code_xrefs"],
        "method_pointer_holders": [{
            "holder_rva": row["holder_rva"],
            "target_rva": row["target_rva"],
            "code_xref_count": len(row["code_xrefs"]),
        } for row in report["request_method_pointer_holders"]["holders"][:40]],
        "warning": "Direct call and type references do not prove which area wins at runtime",
    }, indent=2), flush=True)
    print("WORLD_AREA_NATIVE_SUMMARY_END", flush=True)


if __name__ == "__main__":
    main()
