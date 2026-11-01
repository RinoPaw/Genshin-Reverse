"""Original sector-root binary layout regression tests."""
import json
from pathlib import Path
import struct
import unittest

from genshinre.sectorroot71 import parse_sector_root


def string(text):
    raw = text.encode("utf-8")
    return struct.pack("<I",len(raw)) + raw + b"\x00"*((-len(raw))%4)


def sample(manual=False, sector_names=("BW_Sample_0_0",), blacklist=()):
    return b"".join((
        struct.pack("<iq",0,123),
        bytes((1,0,0,0)),
        struct.pack("<iq",0,-234),
        string(""),
        string("DungeonConfig"),
        string("BW_Sample"),
        bytes((int(manual),0,0,0)),
        struct.pack("<I",len(sector_names)),
        b"".join(map(string,sector_names)),
        struct.pack("<I",len(blacklist)),
        b"".join(map(string,blacklist)),
    ))


class OriginalSectorRootTests(unittest.TestCase):
    def test_preserves_exact_name_lists(self):
        data = sample(True,("BW_Sample_0_0","BW_Sample_-1_0"),("blocked",))
        root = parse_sector_root(data)
        self.assertEqual(123, root.game_object_path_id)
        self.assertEqual(-234, root.script_path_id)
        self.assertTrue(root.manual_load)
        self.assertTrue(root.enabled)
        self.assertEqual("DungeonConfig", root.config_name)
        self.assertEqual("BW_Sample", root.world_name)
        self.assertEqual(("BW_Sample_0_0","BW_Sample_-1_0"), root.sectors)
        self.assertEqual(("blocked",),root.blacklisted_sectors)

    def test_consumes_exact_source_bytes(self):
        payload = sample()
        self.assertEqual("BW_Sample_0_0",parse_sector_root(payload).sectors[0])
        for malformed in (payload[:-1],payload + b"\x00"):
            with self.subTest(length=len(malformed)):
                with self.assertRaises(ValueError):
                    parse_sector_root(malformed)

    def test_pinned_root_evidence_has_no_world_height_claim(self):
        path = (Path(__file__).resolve().parents[1] /
                "versions/7.1.0-global/analyses/world/7.1-native-serialized-sector-roots.json")
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(7,evidence["verifiedRootCount"])
        self.assertFalse(evidence["limits"]["safeServerRaycastEnabled"])
        worlds = {entry["world_name"] for entry in evidence["roots"]}
        self.assertIn("BW_BirdPinball",worlds)
        self.assertIn("BW_Custom_Edit01",worlds)


if __name__ == "__main__":
    unittest.main()
