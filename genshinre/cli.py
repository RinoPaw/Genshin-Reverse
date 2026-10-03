from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import research_status
from .anchors import verify_metadata_anchors
from .fingerprint import fingerprint
from .getcmdid import scan_constant_cmdids
from .metadata import build_type_methods, query_fields, query_methods
from .mhy71 import decode_metadata_71
from .opcodes import crosscheck_registry, import_java_opcodes, write_crosscheck
from .pointerxref import scan_pointer_xrefs
from .protocolquery import query_protocol
from .registry import query_registry
from .scaffold import scaffold
from .scenehandlers import extract_scene_handler_slots
from .trace import import_trace
from .validate import validate_version
from .wire import parse_message
from .xrefs import inspect_rva, probe_registry_71, scan_rip_xrefs, write_json


def _rva(text: str) -> int:
    return int(text, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genshinre")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fingerprint", help="hash local samples and identify basic file/PE format")
    p.add_argument("files", nargs="+", type=Path)

    p = sub.add_parser("wire", help="decode protobuf wire fields from hex")
    p.add_argument("hex_payload")

    p = sub.add_parser("query-registry", help="stream-query a registry.csv by identity fields")
    p.add_argument("registry", type=Path)
    p.add_argument("--cmd-id", type=int)
    p.add_argument("--type")
    p.add_argument("--type-definition-index", type=int)
    p.add_argument("--index", type=int, dest="registry_index")

    p = sub.add_parser("protocol-query", help="join published protocol evidence around a registry identity")
    p.add_argument("version_dir", type=Path)
    p.add_argument("--cmd-id", type=int)
    p.add_argument("--type")
    p.add_argument("--type-definition-index", type=int)
    p.add_argument("--index", type=int, dest="registry_index")

    p = sub.add_parser("import-opcodes-java", help="extract a numeric opcode control set from PacketOpcodes.java")
    p.add_argument("java_file", type=Path)
    p.add_argument("output_csv", type=Path)

    p = sub.add_parser("crosscheck-registry", help="verify that a registry contains every control-set CmdId")
    p.add_argument("registry", type=Path)
    p.add_argument("control_set", type=Path)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("import-trace", help="turn server RECV/SEND trace lines into packet trace CSV")
    p.add_argument("input_log", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("--source", default="")

    p = sub.add_parser("build-type-methods", help="build a type -> methods JSON index from metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)

    p = sub.add_parser("query-methods", help="stream-query metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("--type")
    p.add_argument("--type-definition-index", type=int)
    p.add_argument("--parameter-type")
    p.add_argument("--method-name")

    p = sub.add_parser("query-fields", help="stream-query metadata/fields.csv")
    p.add_argument("fields_csv", type=Path)
    p.add_argument("--type")
    p.add_argument("--type-definition-index", type=int)
    p.add_argument("--field-name")
    p.add_argument("--field-type")
    p.add_argument("--field-type-index", type=int)

    p = sub.add_parser("scan-constant-cmdids", help="scan method RVAs for conservative constant-return CmdId candidates")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("--summary", type=Path)
    p.add_argument("--min-id", type=int, default=1)
    p.add_argument("--max-id", type=int, default=65535)

    p = sub.add_parser("rip-xrefs", help="scan simple x86-64 RIP-relative MOV/LEA xrefs to target RVAs")
    p.add_argument("exe", type=Path)
    p.add_argument("target_rvas", nargs="+", type=_rva)
    p.add_argument("--window", type=int, default=24)
    p.add_argument("--all-sections", action="store_true")
    p.add_argument("--output", type=Path)

    p = sub.add_parser(
        "pointer-xrefs",
        help="find data qword holders pointing into an RVA range, then code xrefs to those holders",
    )
    p.add_argument("exe", type=Path)
    p.add_argument("target_start_rva", type=_rva)
    p.add_argument("target_end_rva", type=_rva)
    p.add_argument("--alignment", type=int, default=8)
    p.add_argument("--window", type=int, default=48)
    p.add_argument("--include-executable-holders", action="store_true")
    p.add_argument("--output", type=Path)

    p = sub.add_parser(
        "scene-handler-slots",
        help="join one-parameter scene-owner protocol methods to verified delegate-slot loads",
    )
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("owner_type")
    p.add_argument("slot_start", type=_rva)
    p.add_argument("slot_end", type=_rva)
    p.add_argument("--alignment", type=int, default=8)
    p.add_argument("--max-method-body", type=_rva, default=0x10000)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("inspect-rva", help="dump bytes and simple RIP-relative instructions around an RVA")
    p.add_argument("exe", type=Path)
    p.add_argument("rva", type=_rva)
    p.add_argument("--before", type=int, default=32)
    p.add_argument("--after", type=int, default=64)
    p.add_argument("--output", type=Path)

    p = sub.add_parser("probe-registry-71", help="probe preserved 7.1 type-slot/store-site registry anchors")
    p.add_argument("exe", type=Path)
    p.add_argument("output_json", type=Path)

    p = sub.add_parser("decode-metadata-71", help="decode the exact preserved 7.1 Global MHY metadata sample")
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("output_dir", type=Path)

    p = sub.add_parser("verify-metadata", help="verify metadata indexes against preserved target-version anchors")
    p.add_argument("metadata_dir", type=Path)
    p.add_argument("anchors_json", type=Path)

    p = sub.add_parser("scaffold", help="create a version/platform artifact tree")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--version", required=True)
    p.add_argument("--region", default="global")
    p.add_argument("--platform", default="windows-x64")

    p = sub.add_parser("research-status", help="summarize machine-readable analysis state and open claims")
    p.add_argument("path", type=Path)

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
        if not any(
            (
                args.cmd_id is not None,
                args.type,
                args.type_definition_index is not None,
                args.registry_index is not None,
            )
        ):
            raise SystemExit("provide --cmd-id, --type, --type-definition-index or --index")
        rows = query_registry(
            args.registry,
            cmd_id=args.cmd_id,
            type_name=args.type,
            type_definition_index=args.type_definition_index,
            registry_index=args.registry_index,
        )
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "protocol-query":
        if not any(
            (
                args.cmd_id is not None,
                args.type,
                args.type_definition_index is not None,
                args.registry_index is not None,
            )
        ):
            raise SystemExit("provide --cmd-id, --type, --type-definition-index or --index")
        result = query_protocol(
            args.version_dir,
            cmd_id=args.cmd_id,
            type_name=args.type,
            type_definition_index=args.type_definition_index,
            registry_index=args.registry_index,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result["result_count"] == 0:
            raise SystemExit(1)
    elif args.command == "import-opcodes-java":
        print(import_java_opcodes(args.java_file, args.output_csv))
    elif args.command == "crosscheck-registry":
        result = crosscheck_registry(args.registry, args.control_set)
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
        if not any((args.type, args.parameter_type, args.method_name, args.type_definition_index is not None)):
            raise SystemExit("provide --type, --type-definition-index, --parameter-type or --method-name")
        rows = query_methods(
            args.methods_csv,
            type_name=args.type,
            parameter_type=args.parameter_type,
            method_name=args.method_name,
            type_definition_index=args.type_definition_index,
        )
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "query-fields":
        if not any(
            (
                args.type,
                args.field_name,
                args.field_type,
                args.type_definition_index is not None,
                args.field_type_index is not None,
            )
        ):
            raise SystemExit(
                "provide --type, --type-definition-index, --field-name, --field-type or --field-type-index"
            )
        rows = query_fields(
            args.fields_csv,
            type_name=args.type,
            field_name=args.field_name,
            field_type=args.field_type,
            type_definition_index=args.type_definition_index,
            field_type_index=args.field_type_index,
        )
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "scan-constant-cmdids":
        result = scan_constant_cmdids(
            args.exe,
            args.methods_csv,
            args.output_csv,
            summary_json=args.summary,
            min_cmd_id=args.min_id,
            max_cmd_id=args.max_id,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "rip-xrefs":
        result = scan_rip_xrefs(
            args.exe,
            args.target_rvas,
            window=args.window,
            executable_sections_only=not args.all_sections,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "pointer-xrefs":
        result = scan_pointer_xrefs(
            args.exe,
            args.target_start_rva,
            args.target_end_rva,
            alignment=args.alignment,
            window=args.window,
            include_executable_holders=args.include_executable_holders,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "scene-handler-slots":
        result = extract_scene_handler_slots(
            args.exe,
            args.methods_csv,
            args.registry_csv,
            args.owner_type,
            args.slot_start,
            args.slot_end,
            slot_alignment=args.alignment,
            max_method_body=args.max_method_body,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "inspect-rva":
        result = inspect_rva(args.exe, args.rva, before=args.before, after=args.after)
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "probe-registry-71":
        result = probe_registry_71(args.exe)
        write_json(result, args.output_json)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "decode-metadata-71":
        result = decode_metadata_71(args.exe, args.metadata, args.output_dir)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "verify-metadata":
        result = verify_metadata_anchors(args.metadata_dir, args.anchors_json)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if not result["passed"]:
            raise SystemExit(1)
    elif args.command == "scaffold":
        print(scaffold(args.root, args.version, args.region, args.platform))
    elif args.command == "research-status":
        print(json.dumps(research_status(args.path), indent=2, ensure_ascii=False))
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
