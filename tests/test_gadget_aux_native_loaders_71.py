"""Original-client source and native instruction gates for Gadget aux tables."""
from importlib import util
from pathlib import Path
import copy
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
SPEC = util.spec_from_file_location("gadget_aux_loader_71", ROOT / "scripts/audit-7.1-gadget-aux-native-loaders.py")
mod = util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class NativeAuxGadgetLoaders(unittest.TestCase):
    def test_source_tables_exact_identity(self):
        self.assertEqual(mod.METHODS_BLOB, "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a")
        self.assertEqual({name: value["rowCount"] for name, value in mod.SOURCE.items()},
                         {"GadgetPropExcelConfigData": 326,
                          "GadgetInteractExcelConfigData": 363})

    def test_native_header_decode_rejects_unpinned_bytes(self):
        for source in mod.SOURCE.values():
            payload = struct.pack("<I",
                (source["rowCount"] - int(source["immediate"], 16)) & 0xFFFFFFFF
                if source["operation"] == "add"
                else source["rowCount"] ^ int(source["immediate"], 16)) + b"synthetic"
            raw = struct.pack("<I", len(payload)) + payload
            checks = {**source, "rawSha256": hashlib.sha256(raw).hexdigest(),
                      "payloadSha256": hashlib.sha256(payload).hexdigest()}
            self.assertEqual(mod.decode_header(raw, checks)["nativeDecodedRowCount"],
                             source["rowCount"])
            with self.assertRaisesRegex(ValueError, "Raw SHA-256"):
                mod.decode_header(raw + b"x", checks)

    def test_native_loop_requires_all_original_anchors(self):
        synthetic = {}
        raw = {}
        replace_sources = copy.deepcopy(mod.SOURCE)
        for name, entry in replace_sources.items():
            inst = []
            for rva, (mnemonic, op_str) in entry["anchors"].items():
                inst.append({"rva": rva, "mnemonic": mnemonic, "op_str": op_str,
                             "bytes": "488b0d00000000" if rva == next(
                                key for key, val in entry["anchors"].items()
                                if val[1].startswith("rcx, qword ptr [rip")) else "90"})
            target = next(key for key, val in entry["anchors"].items()
                          if val[1].startswith("rcx, qword ptr [rip"))
            replace_sources[name]["rowClassStaticSlot"] = hex(int(target, 16) + 7)
            synthetic[name] = {"exe_sha256": PROFILE_71.exe_sha256,
                               "start_rva": entry["loaderRva"], "size": 0x320,
                               "instructions": inst}
            payload = struct.pack("<I",
                (entry["rowCount"] - int(entry["immediate"], 16)) & 0xFFFFFFFF
                if entry["operation"] == "add"
                else entry["rowCount"] ^ int(entry["immediate"], 16)) + b"test"
            fake = struct.pack("<I", len(payload)) + payload
            replace_sources[name]["rawSha256"] = hashlib.sha256(fake).hexdigest()
            replace_sources[name]["payloadSha256"] = hashlib.sha256(payload).hexdigest()
            raw[name] = fake
        with patch.dict(mod.SOURCE, replace_sources):
            expected = mod.verify(synthetic, raw, dict.fromkeys(raw, True))
            self.assertFalse(any(x["rowFieldsDecoded"] for x in expected["tables"].values()))
            damaged = copy.deepcopy(synthetic)
            damaged["GadgetPropExcelConfigData"]["instructions"][0]["op_str"] = "eax, eax"
            with self.assertRaisesRegex(ValueError, "instruction mismatch"):
                mod.verify(damaged, raw, dict.fromkeys(raw, True))


if __name__ == "__main__":
    unittest.main()
