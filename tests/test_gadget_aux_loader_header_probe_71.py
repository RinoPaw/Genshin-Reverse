"""Original 7.1 auxiliary Gadget header/native loader candidate logic."""
from importlib import util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("native_aux_71", ROOT / "scripts/probe-7.1-gadget-aux-loaders.py")
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestOriginalAuxGadgetLoader(unittest.TestCase):
    def test_checked_native_add_and_xor(self):
        sample = [{"candidateMovRva": "0x100", "candidateArithmeticRva": "0x105",
                   "immediate": "0x00000009", "operator": "add", "signatureHex": "a"},
                  {"candidateMovRva": "0x200", "candidateArithmeticRva": "0x205",
                   "immediate": "0x0000000B", "operator": "xor", "signatureHex": "b"}]
        head = {"Dummy": {"header": 5, "bytes": 84,
                          "rawSha256": "raw", "payloadSha256": "payload"}}
        result = mod.count_candidates(sample, head)["Dummy"]
        self.assertEqual(result["fourBytesPerRowUpperBound"], 20)
        self.assertEqual([(r["operation"], r["decodedCountIfMatched"])
                          for r in result["candidates"]], [("add", 14), ("xor", 14)])

    def test_out_of_bound_candidates_are_rejected(self):
        result = mod.count_candidates(
            [{"candidateMovRva": "0x100", "candidateArithmeticRva": "0x105",
              "immediate": "0xFFFFFFF0", "operator": "add", "signatureHex": "a"}],
            {"Dummy": {"header": 2, "bytes": 40,
                       "rawSha256": "raw", "payloadSha256": "payload"}})["Dummy"]
        self.assertEqual(result["candidateCount"], 0)

    def test_input_hashes_are_pinned(self):
        self.assertIn("GadgetPropExcelConfigData", mod.SOURCES)
        self.assertIn("GadgetInteractExcelConfigData", mod.SOURCES)
        self.assertEqual(mod.SOURCES["GadgetExcelConfigData"][0], "d65ab32f.dat")


if __name__ == "__main__":
    unittest.main()
