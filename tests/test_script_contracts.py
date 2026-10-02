from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CURRENT_ASTAPS_PACKET_OPCODES = (
    "src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java"
)
LEGACY_ASTAPS_PACKET_OPCODES = (
    "src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java"
)


class ScriptContractTests(unittest.TestCase):
    def test_regeneration_scripts_use_current_astaps_packet_opcodes_path(self) -> None:
        for relative_path in (
            "scripts/regenerate-7.1.sh",
            "scripts/regenerate-7.1.ps1",
        ):
            with self.subTest(script=relative_path):
                text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(CURRENT_ASTAPS_PACKET_OPCODES, text)
                self.assertNotIn(LEGACY_ASTAPS_PACKET_OPCODES, text)


if __name__ == "__main__":
    unittest.main()
