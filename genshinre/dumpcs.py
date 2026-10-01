from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

from .metadata import build_type_methods

NAMESPACE_RE = re.compile(r"^// Namespace:\s*(.*)$")
TYPE_RE = re.compile(
    r"^(?P<mods>.*?)\b(?P<kind>class|struct|enum|interface)\s+"
    r"(?P<name>[^\s:{]+)(?:\s*:\s*(?P<parent>.*?))?\s*"
    r"// TypeDefIndex:\s*(?P<index>\d+)\s*$"
)
RVA_RE = re.compile(r"^// RVA:\s*(?P<rva>0x[0-9A-Fa-f]+)\b")

DECL_MODIFIERS = {
    "public",
    "private",
    "protected",
    "internal",
    "static",
    "virtual",
    "override",
    "abstract",
    "sealed",
    "extern",
    "unsafe",
    "readonly",
    "const",
    "new",
    "async",
    "partial",
    "volatile",
}
PARAM_MODIFIERS = {"ref", "out", "in", "params", "this"}

TYPE_COLUMNS = (
    "type_definition_index",
    "namespace",
    "type_name",
    "parent_type",
    "field_start",
    "field_count",
    "method_start",
    "method_count",
    "type_cache_rva",
    "status",
    "evidence",
)
FIELD_COLUMNS = (
    "field_index",
    "field_ordinal",
    "type_definition_index",
    "type_name",
    "field_name",
    "field_type",
    "offset",
    "status",
    "evidence",
)
METHOD_COLUMNS = (
    "method_index",
    "method_ordinal",
    "type_definition_index",
    "type_name",
    "method_name",
    "rva",
    "return_type",
    "parameter_types",
    "parameters",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normal_address(value: str) -> str:
    return f"0x{int(value, 0):X}"


def _drop_leading_modifiers(text: str, modifiers: set[str]) -> str:
    tokens = text.split()
    while tokens and tokens[0] in modifiers:
        tokens.pop(0)
    return " ".join(tokens)


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    result: list[str] = []
    start = 0
    angle = square = paren = 0
    for index, char in enumerate(text):
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "[":
            square += 1
        elif char == "]" and square:
            square -= 1
        elif char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == delimiter and angle == square == paren == 0:
            result.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        result.append(tail)
    return result


def _parameter_type(parameter: str) -> str:
    parameter = parameter.strip()
    if not parameter:
        return ""
    if " = " in parameter:
        parameter = parameter.split(" = ", 1)[0].strip()
    tokens = parameter.split()
    while tokens and tokens[0] in PARAM_MODIFIERS:
        tokens.pop(0)
    if len(tokens) <= 1:
        return tokens[0] if tokens else ""
    return " ".join(tokens[:-1])


def _parse_field(line: str) -> tuple[str, str, str] | None:
    if "// Offset:" not in line:
        return None
    left, offset = line.rsplit("// Offset:", 1)
    declaration = left.strip()
    if not declaration.endswith(";"):
        return None
    declaration = declaration[:-1].strip()
    if " = " in declaration:
        declaration = declaration.split(" = ", 1)[0].strip()
    tokens = declaration.split()
    if len(tokens) < 2:
        return None
    field_name = tokens[-1]
    field_type = _drop_leading_modifiers(" ".join(tokens[:-1]), DECL_MODIFIERS)
    if not field_type:
        return None
    return field_name, field_type, _normal_address(offset.strip())


def _parse_method(line: str) -> tuple[str, str, list[str], str] | None:
    declaration = line.strip()
    if not declaration.endswith(";") or "(" not in declaration or ")" not in declaration:
        return None
    declaration = declaration[:-1].strip()
    open_paren = declaration.find("(")
    close_paren = declaration.rfind(")")
    if close_paren < open_paren:
        return None
    head = declaration[:open_paren].strip()
    parameters = declaration[open_paren + 1 : close_paren].strip()
    tokens = head.split()
    if len(tokens) < 2:
        return None
    method_name = tokens[-1]
    return_type = _drop_leading_modifiers(" ".join(tokens[:-1]), DECL_MODIFIERS)
    parameter_items = _split_top_level(parameters) if parameters else []
    parameter_types = [ptype for ptype in map(_parameter_type, parameter_items) if ptype]
    return method_name, return_type, parameter_types, parameters


def parse_dump_cs(path: Path) -> dict[str, list[dict[str, str]]]:
    types: list[dict[str, str]] = []
    fields: list[dict[str, str]] = []
    methods: list[dict[str, str]] = []

    namespace = ""
    current_type: dict[str, str] | None = None
    pending_rva = ""
    field_ordinal = 0
    method_ordinal = 0

    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            namespace_match = NAMESPACE_RE.match(line)
            if namespace_match:
                namespace = namespace_match.group(1).strip()
                continue

            type_match = TYPE_RE.match(line)
            if type_match:
                current_type = {
                    "type_definition_index": type_match.group("index"),
                    "namespace": namespace,
                    "type_name": type_match.group("name"),
                    "parent_type": (type_match.group("parent") or "").strip(),
                    "field_start": "",
                    "field_count": "0",
                    "method_start": "",
                    "method_count": "0",
                    "type_cache_rva": "",
                    "status": "",
                    "evidence": "dump.cs",
                }
                types.append(current_type)
                pending_rva = ""
                continue

            if current_type is None:
                continue

            rva_match = RVA_RE.match(line)
            if rva_match:
                pending_rva = _normal_address(rva_match.group("rva"))
                continue

            if pending_rva:
                parsed_method = _parse_method(line)
                if parsed_method:
                    method_name, return_type, parameter_types, parameters = parsed_method
                    methods.append(
                        {
                            "method_index": "",
                            "method_ordinal": str(method_ordinal),
                            "type_definition_index": current_type["type_definition_index"],
                            "type_name": current_type["type_name"],
                            "method_name": method_name,
                            "rva": pending_rva,
                            "return_type": return_type,
                            "parameter_types": json.dumps(parameter_types, ensure_ascii=False),
                            "parameters": parameters,
                            "status": "",
                            "evidence": "dump.cs",
                        }
                    )
                    method_ordinal += 1
                    current_type["method_count"] = str(int(current_type["method_count"]) + 1)
                    pending_rva = ""
                    continue
                if line.startswith("//"):
                    continue
                pending_rva = ""

            parsed_field = _parse_field(line)
            if parsed_field:
                field_name, field_type, offset = parsed_field
                fields.append(
                    {
                        "field_index": "",
                        "field_ordinal": str(field_ordinal),
                        "type_definition_index": current_type["type_definition_index"],
                        "type_name": current_type["type_name"],
                        "field_name": field_name,
                        "field_type": field_type,
                        "offset": offset,
                        "status": "",
                        "evidence": "dump.cs",
                    }
                )
                field_ordinal += 1
                current_type["field_count"] = str(int(current_type["field_count"]) + 1)
                continue

            if line == "}":
                current_type = None
                pending_rva = ""

    return {"types": types, "fields": fields, "methods": methods}


def _write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def import_dump_cs(
    dump_cs: Path,
    output_dir: Path,
    source_tool: str = "Il2CppDumper-style dump.cs",
    tool_revision: str = "",
    provenance: dict[str, object] | None = None,
) -> dict[str, object]:
    parsed = parse_dump_cs(dump_cs)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_csv(output_dir / "types.csv", TYPE_COLUMNS, parsed["types"])
    _write_csv(output_dir / "fields.csv", FIELD_COLUMNS, parsed["fields"])
    _write_csv(output_dir / "methods.csv", METHOD_COLUMNS, parsed["methods"])
    build_type_methods(output_dir / "methods.csv", output_dir / "type-methods.json")

    summary: dict[str, object] = {
        "source": str(dump_cs),
        "source_sha256": _sha256(dump_cs),
        "source_tool": source_tool,
        "tool_revision": tool_revision,
        "type_count": len(parsed["types"]),
        "field_count": len(parsed["fields"]),
        "method_count": len(parsed["methods"]),
        "true_method_indices_available": False,
        "true_field_indices_available": False,
        "notes": [
            "dump.cs preserves TypeDefIndex and method RVA, but does not expose the original global method/field index",
            "method_ordinal and field_ordinal are dump-order identifiers only",
        ],
    }
    if provenance:
        summary["provenance"] = provenance
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary
