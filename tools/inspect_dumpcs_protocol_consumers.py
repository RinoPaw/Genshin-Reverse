from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

TYPE_RE = re.compile(r"^(?P<decl>.*?)\b(?:class|struct|interface)\s+(?P<name>[^\s:{]+).*// TypeDefIndex:\s*(?P<index>\d+)\s*$")
RVA_RE = re.compile(r"^// RVA:\s*(0x[0-9A-Fa-f]+)\b")
TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{5,}\b")


def load_packet_ids(path: Path | None) -> dict[str, int]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    return {str(name): int(cmd) for name, cmd in raw.items()}


def parse_dump(path: Path, packet_ids: dict[str, int]) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    methods: list[dict[str, object]] = []
    types: dict[str, dict[str, object]] = {}
    owner_name = ""
    owner_index: int | None = None
    pending_rva: str | None = None

    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_number, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue

            type_match = TYPE_RE.match(line)
            if type_match:
                owner_name = type_match.group("name")
                owner_index = int(type_match.group("index"))
                types[owner_name] = {
                    "type_name": owner_name,
                    "type_definition_index": owner_index,
                    "declaration": line,
                    "line": line_number,
                }
                pending_rva = None
                continue

            rva_match = RVA_RE.match(line)
            if rva_match:
                pending_rva = rva_match.group(1).upper().replace("0X", "0x")
                continue

            if pending_rva is None or not owner_name:
                continue
            if "(" not in line or ")" not in line:
                if not line.startswith("//"):
                    pending_rva = None
                continue

            protocol_tokens = sorted({token for token in TOKEN_RE.findall(line) if token in packet_ids})
            methods.append(
                {
                    "owner_type": owner_name,
                    "owner_type_definition_index": owner_index,
                    "rva": pending_rva,
                    "line": line_number,
                    "signature": line,
                    "protocol_tokens": [
                        {"type_name": token, "cmd_id": packet_ids[token]} for token in protocol_tokens
                    ],
                }
            )
            pending_rva = None

    return methods, types


def main() -> None:
    p = argparse.ArgumentParser(description="Inspect protocol-type consumers in an Il2CppDumper-style dump.cs.")
    p.add_argument("dump_cs", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--packet-ids", type=Path)
    p.add_argument("--target", action="append", required=True)
    p.add_argument("--neighbors", type=int, default=20)
    args = p.parse_args()

    packet_ids = load_packet_ids(args.packet_ids)
    methods, types = parse_dump(args.dump_cs, packet_ids)
    methods_by_owner: dict[str, list[dict[str, object]]] = defaultdict(list)
    for method in methods:
        methods_by_owner[str(method["owner_type"])].append(method)

    target_rows = []
    for target in args.target:
        target_type = types.get(target)
        hits = [m for m in methods if target in str(m["signature"])]
        external_hits = [m for m in hits if m["owner_type"] != target]
        enriched = []
        for hit in external_hits:
            band = methods_by_owner[str(hit["owner_type"])]
            pos = next(i for i, row in enumerate(band) if row is hit)
            lo = max(0, pos - args.neighbors)
            hi = min(len(band), pos + args.neighbors + 1)
            enriched.append(
                {
                    **hit,
                    "owner_method_position": pos,
                    "owner_method_count": len(band),
                    "neighbor_methods": band[lo:hi],
                }
            )
        target_rows.append(
            {
                "target_type": target,
                "target_cmd_id": packet_ids.get(target),
                "target_type_definition": target_type,
                "all_signature_hit_count": len(hits),
                "external_signature_hit_count": len(external_hits),
                "external_hits": enriched,
            }
        )

    result = {
        "dump_cs": str(args.dump_cs),
        "method_count": len(methods),
        "type_count": len(types),
        "packet_id_count": len(packet_ids),
        "targets": target_rows,
        "notes": [
            "owner_type is the latest dump.cs type declaration carrying a TypeDefIndex before the method RVA/signature",
            "external hits exclude methods owned by the target protobuf type itself",
            "protocol_tokens are annotated from the supplied historical packetIds mapping and are hints for semantic neighborhood reconstruction",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for target in target_rows:
        print("===", target["target_type"], "cmd", target["target_cmd_id"], "===")
        print("typedef", target["target_type_definition"])
        print("external hits", target["external_signature_hit_count"])
        for hit in target["external_hits"]:
            print(hit["rva"], hit["owner_type"], hit["owner_type_definition_index"], hit["signature"])
            print(" neighborhood:")
            for row in hit["neighbor_methods"]:
                marker = ">" if row["line"] == hit["line"] else " "
                tokens = ", ".join(f"{x['type_name']}={x['cmd_id']}" for x in row["protocol_tokens"])
                print(marker, row["rva"], row["signature"], tokens)


if __name__ == "__main__":
    main()
