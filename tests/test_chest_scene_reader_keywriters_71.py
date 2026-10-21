"""Regression for original Global 7.1 native row wrapped-key writer screening."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-scene-reader-keywriters.py"
spec = importlib.util.spec_from_file_location("scene_keywriter_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestSceneKeywriterProbe71(unittest.TestCase):
    def test_native_exact_wrapped_key_writer_and_offsets(self):
        self.assertEqual(probe.WRITER, 0xBB16020)
        self.assertEqual(probe.METHODS_BLOB,
                         "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a")
        self.assertEqual(probe.KEY_OFFSETS, {"SceneTag": 0x28, "SceneExcel": 0x50})
        self.assertEqual(probe.READER_PARAM, '["FNIAHJGHFAK"]')

    def test_aligned_postcall_field_store_screen(self):
        ins = [
            {"mnemonic":"mov", "op_str":"eax, dword ptr [rsp + 0x20]"},
            {"mnemonic":"mov", "op_str":"dword ptr [r15 + 0x28], eax"},
            {"mnemonic":"mov", "op_str":"dword ptr [rbx + 0x50], eax"},
            {"mnemonic":"mov", "op_str":"dword ptr [rsi + 0x30], eax"},
            {"mnemonic":"cmp", "op_str":"dword ptr [r13 + 0x28], eax"},
            {"mnemonic":"mov", "op_str":"dword ptr [r15 + 0x28], edx"},
            {"mnemonic":"mov", "op_str":"qword ptr [rbx + 0x50], rax"},
        ]
        self.assertEqual(probe.classify_post_call(ins), [0x28, 0x50, 0x30])
        self.assertEqual(probe.classify_post_call([]), [])

    def test_source_metadata_blob_hash_is_git_blob_not_file_sha(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td)/"methods.csv"
            f.write_bytes(b"abcd")
            self.assertEqual(probe.git_blob(f),
                             hashlib.sha1(b"blob 4\0abcd").hexdigest())


if __name__ == "__main__":
    unittest.main()
