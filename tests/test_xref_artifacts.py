from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.xrefartifacts import validate_xref_directory, validate_xref_table


class XrefArtifactTests(unittest.TestCase):
    def test_committed_xref_seed_tables_match_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "versions/7.1.0-global/windows-x64/xrefs"
        self.assertEqual([], validate_xref_directory(path))

    def test_rejects_bad_handler_rva(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "message-handlers.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "cmd_id",
                        "type_name",
                        "direction",
                        "handler_type",
                        "handler_method",
                        "handler_rva",
                        "status",
                        "evidence",
                        "context",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "cmd_id": "22899",
                        "type_name": "ONKOPMILDMF",
                        "direction": "S2C",
                        "handler_type": "LLCGIEDMIIG",
                        "handler_method": "MACAMCMOKOL",
                        "handler_rva": "C227790",
                        "status": "CONFIRMED",
                        "evidence": "test evidence",
                        "context": "test context",
                    }
                )

            errors = validate_xref_table(path)
            self.assertTrue(any("bad handler_rva" in error for error in errors))

    def test_blank_recovered_names_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "message-senders.csv"
            path.write_text(
                "cmd_id,type_name,sender_type,sender_method,sender_rva,context,status,evidence\n"
                "26105,HJDNCHODGOL,,,0x725CEF0,login,CONFIRMED,client audit\n",
                encoding="utf-8",
            )
            self.assertEqual([], validate_xref_table(path))


if __name__ == "__main__":
    unittest.main()
