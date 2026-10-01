from __future__ import annotations

import csv
import re
from pathlib import Path

TRACE_RE = re.compile(
    r"^(?P<timestamp>\d{2}:\d{2}:\d{2})?.*?"
    r"(?P<direction>RECV|SEND)\s+cmdId=(?P<cmd_id>-?\d+)\s+"
    r"name=(?P<name>\S+)\s+len=(?P<length>\d+)"
    r".*?payload=(?P<payload><empty>|[0-9A-Fa-f]+)"
)
OFFSET_RE = re.compile(r"\+(?P<offset>\d+)ms")

COLUMNS = ("timestamp", "offset_ms", "direction", "cmd_id", "name", "length", "payload_hex", "source")


def parse_trace_line(line: str, source: str = "") -> dict[str, str] | None:
    match = TRACE_RE.search(line.strip())
    if not match:
        return None
    direction = "C2S" if match.group("direction") == "RECV" else "S2C"
    offset = OFFSET_RE.search(line)
    payload = match.group("payload")
    return {
        "timestamp": match.group("timestamp") or "",
        "offset_ms": offset.group("offset") if offset else "",
        "direction": direction,
        "cmd_id": match.group("cmd_id"),
        "name": match.group("name"),
        "length": match.group("length"),
        "payload_hex": "" if payload == "<empty>" else payload.lower(),
        "source": source,
    }


def import_trace(input_path: Path, output_csv: Path, source: str = "") -> int:
    rows = []
    for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
        row = parse_trace_line(line, source=source or input_path.name)
        if row:
            rows.append(row)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)
