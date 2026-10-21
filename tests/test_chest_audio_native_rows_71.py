"""Synthetic source byte tests for original 7.1 chest audio row wire reader."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "chest_audio_native_rows_71", ROOT / "scripts/audit-7.1-chest-audio-native-rows.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def row(prewrapper_id: int, class_scalar: int | None = None, mask_override=None) -> bytes:
    mask = (0x10 | (0x20 if class_scalar is not None else 0)) if mask_override is None else mask_override
    mask_raw = (((mask - mod.PRESENCE_ADD) & mod.U16) ^
                (mod.PRESENCE_XOR & mod.U16))
    raw = struct.pack("<H", mask_raw)
    if class_scalar is not None:
        raw += struct.pack("<I", (class_scalar - mod.AUDIO_FIELD_ADD) & mod.U32)
    raw += struct.pack("<I", (prewrapper_id - mod.KEY_FIELD_ADD) & mod.U32)
    return raw


def table(rows: list[bytes]) -> bytes:
    return struct.pack("<I", len(rows) ^ mod.COUNT_XOR) + b"".join(rows)


class NativeAudioChestRowsTests(unittest.TestCase):
    def test_exact_native_mask_and_two_field_operations(self):
        first = row(70210001)
        self.assertEqual(first.hex(), "5ef40089dbe7")
        sample = table([first, row(70210031, 1), row(70210041, 2)])
        report = mod.scan_payload(sample)
        self.assertEqual(report["nativeHeaderCount"], 3)
        self.assertEqual(report["bytesConsumed"], len(sample))
        self.assertEqual(report["decodedRecords"], 3)
        self.assertEqual(report["maskLow16Histogram"], {"0x0010": 1, "0x0030": 2})
        self.assertEqual(report["nativeClassScalarHistogram"],
                         {"(absent)": 1, "1": 1, "2": 1})
        self.assertEqual(report["rows"][1]["gadgetIdPreWrapperScalar"], 70210031)
        self.assertEqual(report["uniquePreWrapperGadgetKeyScalars"], 3)

    def test_source_hash_rejects_substitute_inputs(self):
        with self.assertRaisesRegex(ValueError, "Raw SHA-256 mismatch"):
            mod.scan_original(table([row(70210001)]))
        with self.assertRaisesRegex(ValueError, "header"):
            mod.scan_payload(b"123")

    def test_fail_closed_unconsumed_or_bad_keys(self):
        payload = table([row(70210001)])
        with self.assertRaisesRegex(ValueError, "unconsumed"):
            mod.scan_payload(payload + b"extra")
        with self.assertRaisesRegex(ValueError, "duplicate pre-wrapper"):
            mod.scan_payload(table([row(70210001), row(70210001)]))
        with self.assertRaisesRegex(ValueError, "truncated native gadget key"):
            mod.scan_payload(table([row(70210001, 1), row(70210002)[:-1]]))

    def test_missing_native_id_bit_never_gets_an_invented_key(self):
        with self.assertRaisesRegex(ValueError, "missing native gadget key"):
            mod.scan_payload(table([row(70210031, mask_override=0)]))


if __name__ == "__main__":
    unittest.main()
