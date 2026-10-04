from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class ScriptContractTests(unittest.TestCase):
    def test_regeneration_scripts_are_fail_closed_core_only(self) -> None:
        for relative_path in (
            "scripts/regenerate-7.1.sh",
            "scripts/regenerate-7.1.ps1",
        ):
            with self.subTest(script=relative_path):
                text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("decode-metadata-71", text)
                self.assertIn("verify-metadata", text)
                self.assertIn("genshinre.typearray", text)
                self.assertIn("scan-constant-cmdids", text)
                self.assertNotIn("optional", text.lower())
                self.assertNotIn("AstaPS", text)
                self.assertNotIn("registrygraph", text)
                self.assertNotIn("metausage", text)
                self.assertNotIn("usagejoin", text)

    def test_publish_scripts_share_one_package_entrypoint(self) -> None:
        for relative_path in (
            "scripts/publish-artifacts-7.1.sh",
            "scripts/publish-artifacts-7.1.ps1",
        ):
            with self.subTest(script=relative_path):
                text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertEqual(1, text.count("genshinre.artifactpublish"))
                self.assertNotIn("registrygraph", text)
                self.assertNotIn("metausage", text)
                self.assertNotIn("usagejoin", text)

    def test_powershell_path_wrappers_preserve_rooted_paths(self) -> None:
        for relative_path in (
            "scripts/regenerate-7.1.ps1",
            "scripts/publish-artifacts-7.1.ps1",
        ):
            with self.subTest(script=relative_path):
                text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("[System.IO.Path]::IsPathRooted", text)

    def test_heavy_generation_is_one_fail_closed_canonical_chain(self) -> None:
        text = (REPO_ROOT / ".github/workflows/generate-7.1-data.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("RinoPaw/AstaPS", text)
        self.assertNotIn("--astaps", text)
        self.assertNotIn("best-effort", text.lower())
        self.assertIn("Regenerate exact-sample metadata and GetCmdId evidence", text)
        self.assertIn("genshinre.registryslots", text)
        self.assertIn("genshinre.registryslotxref", text)
        self.assertIn("genshinre.registryxrefpublish", text)
        self.assertIn("Publish validated artifacts into version tree", text)
        self.assertIn("Validate published version tree", text)


if __name__ == "__main__":
    unittest.main()
