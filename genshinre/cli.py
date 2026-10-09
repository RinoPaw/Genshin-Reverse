from __future__ import annotations

import argparse
import json
from pathlib import Path


def _rva(text: str) -> int:
    return int(text, 0)


def _label_path(text: str) -> tuple[str, Path]:
    label, sep, raw_path = text.partition("=")
    if not sep or not label or not raw_path:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    return label, Path(raw_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genshinre")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fingerprint", help="hash local samples and identify basic file/PE format")
    p.add_argument("files", nargs="+", type=Path)

    p = sub.add_parser("wire", help="decode protobuf wire fields from hex")
    p.add_argument("hex_payload")

    p = sub.add_parser("query-assets", help="probe exact paths in a Raw-exported design AssetIndex")
    p.add_argument("asset_index", type=Path)
    p.add_argument("paths", nargs="+")

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

    p = sub.add_parser(
        "correlate-capture",
        help="correlate request/response CmdIds in an NDJSON packet-probe capture",
    )
    p.add_argument("capture", type=Path)
    p.add_argument("--request-cmd", type=_rva, required=True)
    p.add_argument(
        "--candidate-cmd",
        type=_rva,
        action="append",
        required=True,
        dest="candidate_cmds",
        help="candidate response CmdId; repeatable",
    )
    p.add_argument("--sequence-field", type=int, default=3)
    p.add_argument("--after-events", type=int, default=24)
    p.add_argument("--request-direction", default="C2S")
    p.add_argument("--response-direction", default="S2C")
    p.add_argument("--event-kind", default="packet_probe")
    p.add_argument("--output", type=Path)

    p = sub.add_parser("build-type-methods", help="build a type -> methods JSON index from metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)

    p = sub.add_parser("query-methods", help="stream-query metadata/methods.csv")
    p.add_argument("methods_csv", type=Path)
    p.add_argument("--type")
    p.add_argument("--type-definition-index", type=int)
    p.add_argument("--parameter-type")
    p.add_argument("--method-name")
    p.add_argument("--rva", type=_rva)

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

    p = sub.add_parser("call-xrefs", help="scan exact E8 rel32 call xrefs and optionally resolve caller methods")
    p.add_argument("exe", type=Path)
    p.add_argument("target_rvas", nargs="+", type=_rva)
    p.add_argument("--methods-csv", type=Path)
    p.add_argument("--max-method-body", type=_rva, default=0x10000)
    p.add_argument("--window", type=int, default=24)
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

    p = sub.add_parser(
        "decode-quest-bin",
        help="decode a Genshin 7.1 native Data/_BinOutput/Quest payload",
    )
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)

    p = sub.add_parser(
        "quest-coverage",
        help="batch-decode extracted 7.1 Quest payloads and summarize unsupported native shapes",
    )
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--fail-on-error", action="store_true")

    p = sub.add_parser(
        "quest-assets",
        help="resolve MainQuestIndex entries to exact 7.1 design AssetIndex block locations",
    )
    p.add_argument("design_asset_index", type=Path)
    p.add_argument("main_quest_index", type=Path)
    p.add_argument("--output", type=Path)

    p = sub.add_parser(
        "quest-collect",
        help="collect exact Quest payloads from per-block AnimeStudio Raw exports",
    )
    p.add_argument("asset_manifest", type=Path)
    p.add_argument("export_root", type=Path)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--coverage", type=Path)

    p = sub.add_parser("recover", help="recover compatibility data without promoting it to native evidence")
    recover_sub = p.add_subparsers(dest="recover_target", required=True)
    q = recover_sub.add_parser(
        "quest-compat",
        help="build a provenance-preserving acceptCond/beginExec recovery manifest",
    )
    q.add_argument("raw_7_1_root", type=Path)
    q.add_argument("--raw-source", required=True)
    q.add_argument(
        "--community-source",
        type=_label_path,
        action="append",
        required=True,
        metavar="LABEL=PATH",
        help="pinned community projection; repeat for at least two independent sources",
    )
    q.add_argument("--historical-tsv-root", type=Path)
    q.add_argument("--historical-tsv-source")
    q.add_argument("--output", type=Path, required=True)
    q.add_argument("--unresolved-output", type=Path, required=True)

    p = sub.add_parser("audit", help="audit server resources against preserved evidence")
    audit_sub = p.add_subparsers(dest="audit_target", required=True)
    q = audit_sub.add_parser(
        "quest",
        help="audit AstaPS-style Quest JSON against Genshin 7.1 ordinary Quest evidence",
    )
    q.add_argument("raw_7_1_root", type=Path)
    q.add_argument("resource_root", type=Path)
    q.add_argument("--recovery-manifest", type=Path)
    q.add_argument("--output", type=Path)
    q.add_argument("--only-problems", action="store_true")
    q.add_argument("--fail-on-conflict", action="store_true")

    p = sub.add_parser("validate", help="validate a version/platform artifact directory")
    p.add_argument("path", type=Path)
    p.add_argument("--allow-partial", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "fingerprint":
        from .fingerprint import fingerprint

        print(json.dumps([fingerprint(path) for path in args.files], indent=2, ensure_ascii=False))
    elif args.command == "wire":
        from .wire import parse_message

        payload = bytes.fromhex(args.hex_payload.replace(" ", ""))
        print(json.dumps(parse_message(payload), indent=2, ensure_ascii=False))
    elif args.command == "query-assets":
        from .assetindex import parse_asset_index, query_asset_paths

        index = parse_asset_index(args.asset_index.read_bytes())
        print(json.dumps(query_asset_paths(index, args.paths), indent=2, ensure_ascii=False))
    elif args.command == "query-registry":
        from .registry import query_registry

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
        from .protocolquery import query_protocol

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
        from .opcodes import import_java_opcodes

        print(import_java_opcodes(args.java_file, args.output_csv))
    elif args.command == "crosscheck-registry":
        from .opcodes import crosscheck_registry, write_crosscheck

        result = crosscheck_registry(args.registry, args.control_set)
        if args.output:
            write_crosscheck(result, args.output)
        print(json.dumps(result, indent=2))
        if not result["all_control_ids_present"]:
            raise SystemExit(1)
    elif args.command == "import-trace":
        from .trace import import_trace

        print(import_trace(args.input_log, args.output_csv, source=args.source))
    elif args.command == "correlate-capture":
        from .capture import analyze_capture_file
        from .xrefs import write_json

        result = analyze_capture_file(
            args.capture,
            request_cmd=args.request_cmd,
            candidate_cmds=args.candidate_cmds,
            sequence_field=args.sequence_field,
            after_events=args.after_events,
            request_direction=args.request_direction,
            response_direction=args.response_direction,
            event_kind=args.event_kind,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "build-type-methods":
        from .metadata import build_type_methods

        index = build_type_methods(args.methods_csv, args.output_json)
        print(json.dumps({"keys": len(index)}, indent=2))
    elif args.command == "query-methods":
        from .metadata import query_methods

        if not any(
            (
                args.type,
                args.parameter_type,
                args.method_name,
                args.type_definition_index is not None,
                args.rva is not None,
            )
        ):
            raise SystemExit("provide --type, --type-definition-index, --parameter-type, --method-name or --rva")
        rows = query_methods(
            args.methods_csv,
            type_name=args.type,
            parameter_type=args.parameter_type,
            method_name=args.method_name,
            type_definition_index=args.type_definition_index,
            rva=args.rva,
        )
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        if not rows:
            raise SystemExit(1)
    elif args.command == "query-fields":
        from .metadata import query_fields

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
        from .getcmdid import scan_constant_cmdids

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
        from .xrefs import scan_rip_xrefs, write_json

        result = scan_rip_xrefs(
            args.exe,
            args.target_rvas,
            window=args.window,
            executable_sections_only=not args.all_sections,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "call-xrefs":
        from .callxref import scan_direct_call_xrefs
        from .xrefs import write_json

        result = scan_direct_call_xrefs(
            args.exe,
            args.target_rvas,
            methods_csv=args.methods_csv,
            max_method_body=args.max_method_body,
            window=args.window,
        )
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "pointer-xrefs":
        from .pointerxref import scan_pointer_xrefs
        from .xrefs import write_json

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
        from .scenehandlers import extract_scene_handler_slots
        from .xrefs import write_json

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
        from .xrefs import inspect_rva, write_json

        result = inspect_rva(args.exe, args.rva, before=args.before, after=args.after)
        if args.output:
            write_json(result, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "decode-metadata-71":
        from .mhy71 import decode_metadata_71

        result = decode_metadata_71(args.exe, args.metadata, args.output_dir)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "verify-metadata":
        from .anchors import verify_metadata_anchors

        result = verify_metadata_anchors(args.metadata_dir, args.anchors_json)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if not result["passed"]:
            raise SystemExit(1)
    elif args.command == "scaffold":
        from .scaffold import scaffold

        print(scaffold(args.root, args.version, args.region, args.platform))
    elif args.command == "research-status":
        from .analysis import research_status

        print(json.dumps(research_status(args.path), indent=2, ensure_ascii=False))
    elif args.command == "decode-quest-bin":
        from .questbin import parse_main_quest

        quest = parse_main_quest(args.input.read_bytes())
        rendered = quest.to_json()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "quest-coverage":
        from .questcoverage import analyze_quest_path

        result = analyze_quest_path(args.input)
        rendered = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        if args.fail_on_error and result["failed"]:
            raise SystemExit(1)
    elif args.command == "quest-assets":
        from .questresources import build_quest_asset_manifest

        result = build_quest_asset_manifest(
            args.design_asset_index.read_bytes(),
            args.main_quest_index.read_bytes(),
        )
        rendered = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "quest-collect":
        from .questcollect import collect_quest_payloads

        result = collect_quest_payloads(
            args.asset_manifest,
            args.export_root,
            args.output_dir,
            coverage_path=args.coverage,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    elif args.command == "recover":
        if args.recover_target == "quest-compat":
            from .questrecovery71 import (
                build_consensus_from_directories,
                write_json,
            )

            if len(args.community_source) < 2:
                raise SystemExit("quest compatibility recovery requires at least two --community-source values")
            if (args.historical_tsv_root is None) != (args.historical_tsv_source is None):
                raise SystemExit(
                    "--historical-tsv-root and --historical-tsv-source must be provided together"
                )
            community_roots = dict(args.community_source)
            if len(community_roots) != len(args.community_source):
                raise SystemExit("--community-source labels must be unique")
            manifest, unresolved = build_consensus_from_directories(
                args.raw_7_1_root,
                community_roots,
                raw_71_source=args.raw_source,
                historical_tsv_root=args.historical_tsv_root,
                historical_tsv_source=args.historical_tsv_source,
            )
            write_json(args.output, manifest)
            write_json(args.unresolved_output, unresolved)
            print(
                json.dumps(
                    {
                        "manifest": str(args.output),
                        "unresolved": str(args.unresolved_output),
                        "summary": manifest["summary"],
                    },
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
    elif args.command == "audit":
        if args.audit_target == "quest":
            from .questaudit import audit_quest_directories

            result = audit_quest_directories(
                args.raw_7_1_root,
                args.resource_root,
                recovery_manifest_path=args.recovery_manifest,
                only_problems=args.only_problems,
            )
            rendered = json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            if args.fail_on_conflict and result["summary"]["conflicts"]:
                raise SystemExit(1)
    elif args.command == "validate":
        from .validate import validate_version

        errors, warnings = validate_version(args.path, allow_partial=args.allow_partial)
        for warning in warnings:
            print(f"WARNING: {warning}")
        for error in errors:
            print(f"ERROR: {error}")
        if errors:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
