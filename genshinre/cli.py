from __future__ import annotations

import argparse
import json
from pathlib import Path

from .fingerprint import fingerprint
from .metadata import build_type_methods, query_methods
from .opcodes import crosscheck_registry, import_java_opcodes, write_crosscheck
from .registry import normalize_registry, query_registry
from .scaffold import scaffold
from .trace import import_trace
from .validate import validate_version
from .wire import parse_message


def _direction_map(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    result: dict[str, str] = {}
    for item in text.split(","):
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genshinre")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fingerprint", help="hash local samples and inspect basic PE metadata")
    p.add_argument("files", nargs="+", type=Path)

    p = sub.add_parser("wire", help="decode protobuf wire fields from hex")
    p.add_argument("hex_payload")

    p = sub.add_parser("query-registry", help="query canonical registry.csv")
    p.add_argument("registry", type=Path)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--cmd-id", type=int)
    group.add_argument("--type")

    p = sub.add_parser("normalize-registry", help="normalize a recovered registry into canonical CSV/JSON/summary")
    p.add_argument("input_csv", type=Path)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--direction-map", help="raw-to-canonical mapping, e.g. 0=S2C,1=C2S")
    p.add_argument("--provenance", type=Path, help="JSON file copied into summary provenance")

    p = sub.add_parser("import-opcodes-java", help="extract a numeric opcode control set from PacketOpcodes.java")
    p.add_argument("java_file", type=Path)
    p.add_argument("output_csv", type=Path)

    p = sub.add_parser("crosscheck-registry", help="verify that a registry contains every control-set CmdId")
    p.add_argument("registry", type=Path)
    p.add_argument("known_opcodes", type=Path)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("import-trace", help="turn server RECV/SEND trace lines into observations CSV")
    p.add_argument("input_log", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("--source", default="")

    p = sub.add_parser("build-type-methods", help="build a type -> methods JSON index from metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)

    p = sub.add_parser("query-methods", help="query metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("--type")
    p.add_argument("--parameter-type")
    p.add_argument("--method-name")

    p = sub.add_parser("scaffold", help="create a canonical version/platform artifact tree")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--version", required=True)
    p.add_argument("--region", default="global")
    p.add_argument("--platform", default="windows-x64")

    p = sub.add_parser("validate", help="validate a version/platform artifact directory")
    p.add_argument("path", type=Path)
    p.add_argument("--allow-partial", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "fingerprint":
        print(json.dumps([fingerprint(path) for path in args.files], indent=2, ensure_ascii=False))
    elif args.command == "wire":
        payload = bytes.fromhex(args.hex_payload.replace(" ", ""))
        print(json.dumps(parse_message(payload), indent=2, ensure_ascii=False))
    elif args.command == "query-registry":
        rows = query_registry(args.registry, cmd_id=args.cmd_id, type_name=args.type)
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "normalize-registry":
        provenance = None
        if args.provenance:
            provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
        summary = normalize_registry(args.input_csv, args.output_dir, _direction_map(args.direction_map), provenance)
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    elif args.command == "import-opcodes-java":
        print(import_java_opcodes(args.java_file, args.output_csv))
    elif args.command == "crosscheck-registry":
        result = crosscheck_registry(args.registry, args.known_opcodes)
        if args.output:
            write_crosscheck(result, args.output)
        print(json.dumps(result, indent=2))
        if not result["all_control_ids_present"]:
            raise SystemExit(1)
    elif args.command == "import-trace":
        print(import_trace(args.input_log, args.output_csv, source=args.source))
    elif args.command == "build-type-methods":
        index = build_type_methods(args.methods_csv, args.output_json)
        print(json.dumps({"keys": len(index)}, indent=2))
    elif args.command == "query-methods":
        if not any((args.type, args.parameter_type, args.method_name)):
            raise SystemExit("provide --type, --parameter-type or --method-name")
        rows = query_methods(args.methods_csv, args.type, args.parameter_type, args.method_name)
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "scaffold":
        print(scaffold(args.root, args.version, args.region, args.platform))
    elif args.command == "validate":
        errors, warnings = validate_version(args.path, allow_partial=args.allow_partial)
        for warning in warnings:
            print(f"WARNING: {warning}")
        for error in errors:
            print(f"ERROR: {error}")
        if errors:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
