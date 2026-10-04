from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class PackageMetadataTests(unittest.TestCase):
    def test_version_has_one_source_of_truth(self) -> None:
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = config["project"]

        self.assertNotIn("version", project)
        self.assertIn("version", project["dynamic"])
        self.assertEqual(
            "genshinre.__version__",
            config["tool"]["setuptools"]["dynamic"]["version"]["attr"],
        )

    def test_license_uses_pep639_metadata(self) -> None:
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = config["project"]

        self.assertEqual("Apache-2.0", project["license"])
        self.assertEqual(["LICENSE"], project["license-files"])
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())
        self.assertIn("setuptools>=77", config["build-system"]["requires"])


if __name__ == "__main__":
    unittest.main()
