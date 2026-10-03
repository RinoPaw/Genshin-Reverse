from __future__ import annotations

import unittest

from genshinre.cli import build_parser


class CliParserTests(unittest.TestCase):
    def test_query_methods_parses_exact_rva(self) -> None:
        args = build_parser().parse_args(
            ["query-methods", "metadata/methods.csv", "--rva", "0xAABBD80"]
        )

        self.assertEqual("query-methods", args.command)
        self.assertEqual(0xAABBD80, args.rva)

    def test_correlate_capture_parses_transaction_contract(self) -> None:
        args = build_parser().parse_args(
            [
                "correlate-capture",
                "capture.ndjson",
                "--request-cmd",
                "0x2499",
                "--candidate-cmd",
                "36641",
                "--candidate-cmd",
                "0x4F42",
                "--sequence-field",
                "3",
                "--after-events",
                "32",
                "--request-direction",
                "C2S",
                "--response-direction",
                "S2C",
                "--event-kind",
                "packet_probe",
                "--output",
                "capture.analysis.json",
            ]
        )

        self.assertEqual("correlate-capture", args.command)
        self.assertEqual("capture.ndjson", str(args.capture))
        self.assertEqual(9369, args.request_cmd)
        self.assertEqual([36641, 20290], args.candidate_cmds)
        self.assertEqual(3, args.sequence_field)
        self.assertEqual(32, args.after_events)
        self.assertEqual("C2S", args.request_direction)
        self.assertEqual("S2C", args.response_direction)
        self.assertEqual("packet_probe", args.event_kind)
        self.assertEqual("capture.analysis.json", str(args.output))

    def test_call_xrefs_parses_targets_and_method_join(self) -> None:
        args = build_parser().parse_args(
            [
                "call-xrefs",
                "GenshinImpact.exe",
                "0x9ED1F40",
                "0x9ED2100",
                "--methods-csv",
                "metadata/methods.csv",
                "--max-method-body",
                "0x8000",
                "--window",
                "32",
                "--output",
                "calls.json",
            ]
        )

        self.assertEqual("call-xrefs", args.command)
        self.assertEqual([0x9ED1F40, 0x9ED2100], args.target_rvas)
        self.assertEqual("metadata/methods.csv", str(args.methods_csv))
        self.assertEqual(0x8000, args.max_method_body)
        self.assertEqual(32, args.window)
        self.assertEqual("calls.json", str(args.output))

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

    def test_scene_handler_slots_parses_exact_scan_contract(self) -> None:
        args = build_parser().parse_args(
            [
                "scene-handler-slots",
                "GenshinImpact.exe",
                "metadata/methods.csv",
                "registry/registry.csv",
                "KLLNGCPBLMM",
                "0x4B1A90",
                "0x4B3AB0",
                "--alignment",
                "8",
                "--max-method-body",
                "0x8000",
                "--output",
                "scene-handler-slots.json",
            ]
        )

        self.assertEqual("scene-handler-slots", args.command)
        self.assertEqual("KLLNGCPBLMM", args.owner_type)
        self.assertEqual(0x4B1A90, args.slot_start)
        self.assertEqual(0x4B3AB0, args.slot_end)
        self.assertEqual(8, args.alignment)
        self.assertEqual(0x8000, args.max_method_body)
        self.assertEqual("scene-handler-slots.json", str(args.output))


if __name__ == "__main__":
    unittest.main()
