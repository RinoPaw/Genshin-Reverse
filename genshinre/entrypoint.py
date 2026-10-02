from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import cli
from .protocolquery import query_protocol
from .versionvalidate import validate_version


def _protocol_query(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="genshinre protocol-query",
        description="join published protocol evidence around a registry identity",
    )
    parser.add_argument("version_dir", type=Path)
    parser.add_argument("--cmd-id", type=int)
    parser.add_argument("--type")
    parser.add_argument("--type-definition-index", type=int)
    parser.add_argument("--index", type=int, dest="registry_index")
    args = parser.parse_args(argv)

    if not any(
        (
            args.cmd_id is not None,
            args.type,
            args.type_definition_index is not None,
            args.registry_index is not None,
        )
    ):
        parser.error("provide --cmd-id, --type, --type-definition-index or --index")

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


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "protocol-query":
        _protocol_query(sys.argv[2:])
        return

    if sys.argv[1:] in (["-h"], ["--help"]):
        cli.build_parser().print_help()
        print("\nAdditional maintained command:\n  protocol-query   join registry, metadata, xrefs and runtime evidence")
        return

    # Keep the existing parser/command dispatch untouched while replacing only the
    # version-validation implementation with the maintained composed validator.
    cli.validate_version = validate_version
    cli.main()
