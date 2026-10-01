from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.anchors import verify_metadata_anchors
from genshinre.dumpcs import import_dump_cs

SAMPLE_DUMP = r"""
// Namespace: Proto
public class HJDNCHODGOL : Object // TypeDefIndex: 12
{
    // Fields
    public uint avatar_id; // Offset: 0x10
    private string nickname; // Offset: 0x18

    // Methods
    // RVA: 0x10587260 Flags: 0x1
    public virtual uint ABCDEFG();
}

// Namespace: Game
public sealed class LLCGIEDMIIG : Object // TypeDefIndex: 99
{
    // Methods
    // RVA: 0xC227790 Flags: 0x2
    private void MACAMCMOKOL(Dictionary<string, int> lookup, ref ONKOPMILDMF packet);
}
"""


class DumpCsTests(unittest.TestCase):
    def test_import_and_anchor_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dump = root / "dump.cs"
            dump.write_text(SAMPLE_DUMP, encoding="utf-8")
            out = root / "metadata"

            summary = import_dump_cs(dump, out, source_tool="synthetic", tool_revision="test")
            self.assertEqual(2, summary["type_count"])
            self.assertEqual(2, summary["field_count"])
            self.assertEqual(2, summary["method_count"])

            with (out / "methods.csv").open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            handler = next(row for row in rows if row["method_name"] == "MACAMCMOKOL")
            self.assertEqual("0xC227790", handler["rva"])
            self.assertEqual(
                ["Dictionary<string, int>", "ONKOPMILDMF"],
                json.loads(handler["parameter_types"]),
            )

            anchors = root / "anchors.json"
            anchors.write_text(
                json.dumps(
                    {
                        "types": [{"type_name": "HJDNCHODGOL", "type_definition_index": 12}],
                        "methods": [
                            {"type_name": "HJDNCHODGOL", "rva": "0x10587260"},
                            {
                                "type_name": "LLCGIEDMIIG",
                                "method_name": "MACAMCMOKOL",
                                "rva": "0x0C227790",
                                "parameter_types": ["ONKOPMILDMF"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = verify_metadata_anchors(out, anchors)
            self.assertTrue(result["passed"])
            self.assertEqual(0, result["failed_count"])

    def test_bad_anchor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dump = root / "dump.cs"
            dump.write_text(SAMPLE_DUMP, encoding="utf-8")
            out = root / "metadata"
            import_dump_cs(dump, out)
            anchors = root / "anchors.json"
            anchors.write_text(
                json.dumps({"methods": [{"type_name": "HJDNCHODGOL", "rva": "0xDEADBEEF"}]}),
                encoding="utf-8",
            )
            self.assertFalse(verify_metadata_anchors(out, anchors)["passed"])


if __name__ == "__main__":
    unittest.main()
