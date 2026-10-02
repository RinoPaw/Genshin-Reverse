from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.metadata import build_type_methods, query_methods
from genshinre.opcodes import crosscheck_registry, import_java_opcodes
from genshinre.trace import import_trace, parse_trace_line


class TraceTests(unittest.TestCase):
    def test_intro_trace(self) -> None:
        line = "06:32:36 <INFO:X> [BORN-INTRO-TRACE] +2858ms RECV cmdId=186 name=UNKNOWN len=4 cutsceneEndCandidate=false payload=7202d027"
        row = parse_trace_line(line, "probe")
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual("C2S", row["direction"])
        self.assertEqual("186", row["cmd_id"])
        self.assertEqual("2858", row["offset_ms"])
        self.assertEqual("7202d027", row["payload_hex"])

    def test_import_trace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "trace.log"
            out = root / "observations.csv"
            log.write_text("06:32:36 x RECV cmdId=186 name=UNKNOWN len=4 payload=7202d027\n", encoding="utf-8")
            self.assertEqual(1, import_trace(log, out))
            self.assertTrue(out.exists())


class OpcodeTests(unittest.TestCase):
    def test_import_and_crosscheck(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            java = root / "PacketOpcodes.java"
            known = root / "known.csv"
            java.write_text("class X { static final int Foo = 10; static final int Unknown = -1; static final int Bar = 20; }", encoding="utf-8")
            self.assertEqual(2, import_java_opcodes(java, known))
            registry = root / "registry.csv"
            registry.write_text("cmd_id,type_name\n10,A\n20,B\n", encoding="utf-8")
            result = crosscheck_registry(registry, known)
            self.assertTrue(result["all_control_ids_present"])
            self.assertEqual(2, result["matched"])


class MetadataTests(unittest.TestCase):
    def test_parameter_query_and_compact_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            methods = root / "methods.csv"
            methods.write_text(
                'method_index,type_definition_index,type_name,method_name,rva,return_type,parameter_types\n'
                '322028,1,LLCGIEDMIIG,MACAMCMOKOL,0xC227790,void,"[""ONKOPMILDMF""]"\n',
                encoding="utf-8",
            )
            rows = query_methods(methods, parameter_type="ONKOPMILDMF")
            self.assertEqual(1, len(rows))
            index = build_type_methods(methods, root / "type-methods.json")
            self.assertEqual(index["by_type_name"]["LLCGIEDMIIG"], [322028])
            self.assertEqual(index["by_type_definition_index"]["1"], [322028])


if __name__ == "__main__":
    unittest.main()
