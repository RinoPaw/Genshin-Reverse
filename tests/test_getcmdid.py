from __future__ import annotations

import unittest

from genshinre.getcmdid import decode_constant_return


class ConstantReturnTests(unittest.TestCase):
    def test_known_26105_stub(self) -> None:
        decoded = decode_constant_return(bytes.fromhex("B8F9650000C3"))
        self.assertEqual((26105, "mov-eax-imm32-ret"), decoded)

    def test_endbr_and_nops(self) -> None:
        decoded = decode_constant_return(bytes.fromhex("F30F1EFA9090B87359000090C3"))
        self.assertEqual((22899, "mov-eax-imm32-ret"), decoded)

    def test_rejects_non_constant_function(self) -> None:
        self.assertIsNone(decode_constant_return(bytes.fromhex("4883EC28488B01C3")))


if __name__ == "__main__":
    unittest.main()
