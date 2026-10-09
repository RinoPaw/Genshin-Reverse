from __future__ import annotations

import unittest
from pathlib import Path

from genshinre.cli import build_parser


class QuestCliTests(unittest.TestCase):
    def test_audit_quest_parser(self) -> None:
        args = build_parser().parse_args(
            [
                "audit",
                "quest",
                "native",
                "resource",
                "--recovery-manifest",
                "recovery.json",
                "--only-problems",
                "--fail-on-conflict",
            ]
        )
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.audit_target, "quest")
        self.assertEqual(args.raw_7_1_root, Path("native"))
        self.assertEqual(args.resource_root, Path("resource"))
        self.assertEqual(args.recovery_manifest, Path("recovery.json"))
        self.assertTrue(args.only_problems)
        self.assertTrue(args.fail_on_conflict)

    def test_recover_quest_compat_parser(self) -> None:
        args = build_parser().parse_args(
            [
                "recover",
                "quest-compat",
                "native",
                "--raw-source",
                "client-7.1",
                "--community-source",
                "a=a-root",
                "--community-source",
                "b=b-root",
                "--output",
                "manifest.json",
                "--unresolved-output",
                "unresolved.json",
            ]
        )
        self.assertEqual(args.command, "recover")
        self.assertEqual(args.recover_target, "quest-compat")
        self.assertEqual(
            args.community_source,
            [("a", Path("a-root")), ("b", Path("b-root"))],
        )


if __name__ == "__main__":
    unittest.main()
