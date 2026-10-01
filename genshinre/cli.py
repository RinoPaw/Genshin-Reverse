from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import research_status
from .anchors import verify_metadata_anchors
from .dumpcs import import_dump_cs
from .extractors import run_mhydump
from .fingerprint import fingerprint
from .getcmdid import scan_constant_cmdids
from .metadata import build_type_methods, query_methods
from .mhy71 import decode_metadata_71
from .opcodes import crosscheck_registry, import_java_opcodes, write_crosscheck
from .registry import normalize_registry, query_registry
from .scaffold import scaffold
from .trace import import_trace
from .validate import validate_version
from .wire import parse_message
from .xrefs import inspect_rva, probe_registry_71, scan_rip_xrefs, write_json


def _direction_map(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    result: dict[str, str] = {}
    for item in text.split(","):
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _rva(text: str) -> int:
    return int(text, 0)


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
    p.add_argument("--allow-unknown-sample", action="store_true")

    p = sub.add_parser("import-dump-cs", help="convert an Il2CppDumper-style dump.cs into canonical metadata indexes")
    p.add_argument("dump_cs", type=Path)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--source-tool", default="Il2CppDumper-style dump.cs")
    p.add_argument("--tool-revision", default="")

    p = sub.add_parser("extract-metadata", help="run a supported external MHY metadata extractor and index its dump.cs")
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--backend", choices=["mhydump"], default="mhydump")
    p.add_argument("--tool", default="mhydump")
    p.add_argument("--tool-revision", default="")
    p.add_argument("--keep-dump-cs", type=Path)

    p = sub.add_parser("verify-metadata", help="verify metadata indexes against preserved target-version anchors")
    p.add_argument("metadata_dir", type=Path)
    p.add_argument("anchors_json", type=Path)

    p = sub.add_parser("scaffold", help="create a canonical version/platform artifact tree")
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
        result = decode_metadata_71(
            args.exe,
            args.metadata,
            args.output_dir,
            allow_unknown_sample=args.allow_unknown_sample,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "import-dump-cs":
        result = import_dump_cs(args.dump_cs, args.output_dir, args.source_tool, args.tool_revision)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "extract-metadata":
        if args.backend != "mhydump":
            raise SystemExit(f"unsupported backend: {args.backend}")
        result = run_mhydump(
            args.exe,
            args.metadata,
            args.output_dir,
            executable=args.tool,
            tool_revision=args.tool_revision,
            keep_dump_cs=args.keep_dump_cs,
        )
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
