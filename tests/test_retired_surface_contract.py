from __future__ import annotations

import unittest
from pathlib import Path


class RetiredSurfaceContractTests(unittest.TestCase):
    def test_maintained_automation_does_not_reintroduce_retired_surfaces(self) -> None:
        root = Path(__file__).resolve().parents[1]
        forbidden = (
            "type_cache_rva",
            "allow_unknown_sample",
            "optional_registry_artifacts_published",
            "optional_artifacts_published",
            "normalize-registry",
            "close-registry-7.1",
            "publish-registry-7.1",
            "registrypublish",
            "registrylayout",
            "registryusagelayout",
            "usageslots",
        )
        paths = [
            *sorted((root / "scripts").glob("*")),
            *sorted((root / ".github" / "workflows").glob("*.yml")),
        ]
        for path in paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                with self.subTest(path=str(path.relative_to(root)), token=token):
                    self.assertNotIn(token, text)

    def test_exact_sample_bypass_is_absent_from_package_and_tools(self) -> None:
        root = Path(__file__).resolve().parents[1]
        paths = [
            *sorted((root / "genshinre").glob("*.py")),
            *sorted((root / "tools").rglob("*.py")),
            *sorted((root / "scripts").glob("*")),
            *sorted((root / ".github" / "workflows").glob("*.yml")),
        ]
        forbidden = ("allow_unknown_sample", "--allow-unknown-sample")
        for path in paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                with self.subTest(path=str(path.relative_to(root)), token=token):
                    self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
