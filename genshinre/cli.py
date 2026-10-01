from __future__ import annotations

import argparse
import json
from pathlib import Path

from .fingerprint import fingerprint
from .registry import normalize_registry, query_registry
from .scaffold import scaffold
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

    p = sub.add_parser("fingerprint", help="hash a local sample and inspect basic PE metadata")
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
