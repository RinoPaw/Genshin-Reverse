from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


class SampleFetchContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.sh = (self.root / "scripts/fetch-7.1-samples.sh").read_text(encoding="utf-8")
        self.ps1 = (self.root / "scripts/fetch-7.1-samples.ps1").read_text(encoding="utf-8")
        self.hashes = json.loads(
            (self.root / "versions/7.1.0-global/windows-x64/hashes.json").read_text(encoding="utf-8")
        )

    def _value(self, text: str, option: str) -> str:
        match = re.search(rf"{re.escape(option)}\s+['\"]([^'\"]+)['\"]", text)
        self.assertIsNotNone(match, f"missing {option}")
        return match.group(1)  # type: ignore[union-attr]

    def test_shells_pin_same_sophon_source(self) -> None:
        for option in ("--manifest-url", "--chunk-prefix"):
            self.assertEqual(self._value(self.sh, option), self._value(self.ps1, option))

    def test_shell_hashes_match_version_provenance(self) -> None:
        expected_exe = self.hashes["samples"]["GenshinImpact.exe"]["sha256"]
        expected_metadata = self.hashes["samples"]["global-metadata.dat"]["sha256"]

        for text in (self.sh, self.ps1):
            self.assertEqual(self._value(text, "--expected-exe-sha256"), expected_exe)
            self.assertEqual(
                self._value(text, "--expected-metadata-sha256"),
                expected_metadata,
            )

    def test_contract_targets_7_1_global_windows_x64(self) -> None:
        self.assertEqual(self.hashes["game_version"], "7.1.0")
        self.assertEqual(self.hashes["region"], "global")
        self.assertEqual(self.hashes["platform"], "windows-x64")


if __name__ == "__main__":
    unittest.main()
