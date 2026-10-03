from __future__ import annotations

import unittest

from genshinre.cli import build_parser


class CliParserTests(unittest.TestCase):
    def test_pointer_xrefs_parses_hex_rvas_and_defaults(self) -> None:
        args = build_parser().parse_args(
            ["pointer-xrefs", "GenshinImpact.exe", "0x1000", "0x2000"]
        )

        self.assertEqual("pointer-xrefs", args.command)
        self.assertEqual(0x1000, args.target_start_rva)
        self.assertEqual(0x2000, args.target_end_rva)
        self.assertEqual(8, args.alignment)
        self.assertEqual(48, args.window)
        self.assertFalse(args.include_executable_holders)
        self.assertIsNone(args.output)

    def test_pointer_xrefs_parses_explicit_scan_options(self) -> None:
        args = build_parser().parse_args(
            [
                "pointer-xrefs",
                "client.exe",
                "4096",
                "8192",
                "--alignment",
                "16",
                "--window",
                "96",
                "--include-executable-holders",
                "--output",
                "pointer-xrefs.json",
            ]
        )

        self.assertEqual(4096, args.target_start_rva)
        self.assertEqual(8192, args.target_end_rva)
        self.assertEqual(16, args.alignment)
        self.assertEqual(96, args.window)
        self.assertTrue(args.include_executable_holders)
        self.assertEqual("pointer-xrefs.json", str(args.output))


if __name__ == "__main__":
    unittest.main()
