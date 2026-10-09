"""Regression for explicitly B-level source-vs-server talent yield scenarios."""
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = runpy.run_path(str(ROOT / "scripts/compare-7.1-talent-domain-models.py"))


class TalentDomainModelTests(unittest.TestCase):
    def test_jean_1_to_10_materials_and_drop_mismatch(self):
        report = MODEL["compare"](331, 4223)
        self.assertEqual(report["bookRequirements"],
                         {"104304": 3, "104305": 21, "104306": 38})
        self.assertEqual(report["threeToOneEquivalentDemand"], 408)
        native = report["models"]["sourceNodesUnderBConsumerSemantics"]
        private = report["models"]["AstaPSServerProxy"]
        for book, mean in zip(("104304", "104305", "104306"),
                              (2.2, 1.98, 0.22)):
            self.assertAlmostEqual(native["perClaimBookMeans"][book], mean)
        for book, mean in zip(("104304", "104305", "104306"),
                              (2.2, 2.3, 1.55)):
            self.assertAlmostEqual(private["perClaimBookMeans"][book], mean)
        self.assertAlmostEqual(native["greenEquivalentSupply"], 10.12)
        self.assertAlmostEqual(private["greenEquivalentSupply"], 23.05)
        self.assertAlmostEqual(native["ratioEquivalentClaims"], 408 / 10.12)
        self.assertAlmostEqual(private["ratioEquivalentClaims"], 408 / 23.05)
        self.assertIn("NOT expected finishing runs", report["note"])

    def test_unverified_weekday_aggregate_refused(self):
        with self.assertRaises(ValueError):
            MODEL["compare"](331, 4200)


if __name__ == "__main__":
    unittest.main()
