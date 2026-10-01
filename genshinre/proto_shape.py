from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_CMD_ID_RE = re.compile(r"^\s*//\s*CmdId:\s*([0-9]+|-)\s*$")
_MESSAGE_RE = re.compile(r"^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
_FIELD_RE = re.compile(
    r"^\s*(?:(optional|required|repeated)\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*<[^;=]+>)?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([0-9]+)"
    r"(?:\s*\[[^\]]*\])?\s*;"
)
_NESTED_RE = re.compile(r"^\s*(?:oneof|message|enum)\b")


def load_name_translations(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "⇨" in line:
            left, right = line.split("⇨", 1)
        elif "=>" in line:
            left, right = line.split("=>", 1)
        else:
            continue
        left = left.strip()
        right = right.strip()
        if left and right:
            result[left] = right
    return result


def parse_dumped_proto(path: Path) -> list[dict[str, object]]:
    """Parse top-level dumped protobuf messages and their direct fields.

    Genshin protocol dumps annotate registered messages with ``// CmdId: N``.
    This parser intentionally handles only the stable subset needed for shape
    filtering: top-level messages, direct fields, nested-data presence and
    CmdId comments. It is not a general .proto parser.
    """

    lines = path.read_text(encoding="utf-8-sig").splitlines()
    messages: list[dict[str, object]] = []
    pending_cmd_id: int | None = None
    index = 0

    while index < len(lines):
        line = lines[index]
        cmd_match = _CMD_ID_RE.match(line)
        if cmd_match:
            value = cmd_match.group(1)
            pending_cmd_id = None if value == "-" else int(value)
            index += 1
            continue

        message_match = _MESSAGE_RE.match(line)
        if not message_match:
            index += 1
            continue

        type_name = message_match.group(1)
        depth = line.count("{") - line.count("}")
        fields: list[dict[str, object]] = []
        has_nested_data = False
        index += 1

        while index < len(lines) and depth > 0:
            body_line = lines[index]
            depth_before = depth
            if depth_before == 1:
                field_match = _FIELD_RE.match(body_line)
                if field_match:
                    label, field_type, field_name, field_number = field_match.groups()
                    fields.append(
                        {
                            "label": label or "",
                            "type": re.sub(r"\s+", "", field_type),
                            "name": field_name,
                            "number": int(field_number),
                        }
                    )
                elif _NESTED_RE.match(body_line):
                    has_nested_data = True

            depth += body_line.count("{") - body_line.count("}")
            index += 1

        messages.append(
            {
                "cmd_id": pending_cmd_id,
                "type_name": type_name,
                "fields": fields,
                "has_nested_data": has_nested_data,
            }
        )
        pending_cmd_id = None

    return messages


def find_proto_shape(
    proto: Path,
    field_type: str,
    field_number: int,
    *,
    field_name: str | None = None,
    single_field: bool = False,
    translations: Path | None = None,
) -> list[dict[str, object]]:
    names = load_name_translations(translations)
    matches: list[dict[str, object]] = []

    for message in parse_dumped_proto(proto):
        cmd_id = message["cmd_id"]
        if cmd_id is None:
            continue
        fields = message["fields"]
        target_fields = [
            field
            for field in fields
            if field["type"] == field_type
            and field["number"] == field_number
            and (field_name is None or field["name"] == field_name)
        ]
        if not target_fields:
            continue
        if single_field and (len(fields) != 1 or message["has_nested_data"]):
            continue

        type_name = str(message["type_name"])
        matches.append(
            {
                "cmd_id": cmd_id,
                "type_name": type_name,
                "semantic_name": names.get(type_name, ""),
                "fields": fields,
                "has_nested_data": message["has_nested_data"],
            }
        )

    matches.sort(key=lambda row: int(row["cmd_id"]))
    return matches


def write_shape_results(rows: list[dict[str, object]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.proto_shape",
        description="Filter Genshin dumped .proto messages by protobuf field shape.",
    )
    parser.add_argument("proto", type=Path)
    parser.add_argument("--field-type", required=True)
    parser.add_argument("--field-number", required=True, type=int)
    parser.add_argument("--field-name")
    parser.add_argument("--single-field", action="store_true")
    parser.add_argument("--translations", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    rows = find_proto_shape(
        args.proto,
        args.field_type,
        args.field_number,
        field_name=args.field_name,
        single_field=args.single_field,
        translations=args.translations,
    )
    if args.output:
        write_shape_results(rows, args.output)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    if not rows:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
