"""Protect domain ownership of 7.1 progression artifacts."""
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression"
FILES = {
    "character": ("7.1-avatar-material-skill-map.json", "7.1-talent-cost-groups.json"),
    "weapon": (),
    "artifact": (),
    "world": ("7.1-adventure-world-level.json", "7.1-adventure-world-domain-schedule.md"),
    "economy": ("7.1-dungeon-reward-previews.json", "7.1-native-drop-economy.md"),
    "rules": ("7.1-daily-dungeon-schedule.json", "7.1-time-gates.md"),
}

class LayoutTests(unittest.TestCase):
    def test_unique_domain_locations(self):
        for folder, names in FILES.items():
            self.assertTrue((BASE / folder / "README.md").is_file())
            for name in names:
                with self.subTest(name=name):
                    self.assertTrue((BASE / folder / name).is_file())
                    self.assertFalse((BASE / name).exists())

if __name__ == "__main__":
    unittest.main()
