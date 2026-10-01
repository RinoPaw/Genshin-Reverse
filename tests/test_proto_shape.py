from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from genshinre.proto_shape import find_proto_shape, load_name_translations, parse_dumped_proto


class ProtoShapeTests(unittest.TestCase):
    def test_parse_and_filter_single_field(self) -> None:
        text = """\
// CmdId: 9369
message DMMJNICDOHM {
    uint32 SCENE = 12;
    uint32 POINT = 1;
}

// CmdId: 20031
message FAFBCLFFAPM {
    int32 RET = 6;
}

// CmdId: 655
message ILNBEGMLHJF {
    int32 RET = 6;
    uint32 OTHER = 4;
}

// CmdId: 999
message WITH_ONEOF {
    int32 RET = 6;
    oneof VALUE {
        uint32 X = 3;
    }
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            proto = Path(tmp) / "Obfuscated.proto"
            proto.write_text(text, encoding="utf-8")
            parsed = parse_dumped_proto(proto)
            self.assertEqual(parsed[0]["cmd_id"], 9369)
            self.assertEqual([field["number"] for field in parsed[0]["fields"]], [12, 1])

            matches = find_proto_shape(
                proto,
                "int32",
                6,
                field_name="RET",
                single_field=True,
            )
            self.assertEqual([row["cmd_id"] for row in matches], [20031])

    def test_name_translation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proto = root / "Obfuscated.proto"
            proto.write_text(
                "// CmdId: 127\nmessage BICKKHGFDMB {\n    int32 RET = 6;\n}\n",
                encoding="utf-8",
            )
            translations = root / "nameTranslation.txt"
            translations.write_text("BICKKHGFDMB⇨SomeRsp\n", encoding="utf-8")
            self.assertEqual(load_name_translations(translations)["BICKKHGFDMB"], "SomeRsp")
            rows = find_proto_shape(proto, "int32", 6, single_field=True, translations=translations)
            self.assertEqual(rows[0]["semantic_name"], "SomeRsp")


if __name__ == "__main__":
    unittest.main()
