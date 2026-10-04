from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from genshinre.pe import PEImage


class PEImageResourceTests(unittest.TestCase):
    def test_closes_file_when_mmap_creation_fails(self) -> None:
        fake_file = MagicMock()
        with (
            patch.object(Path, "open", return_value=fake_file),
            patch("genshinre.pe.mmap.mmap", side_effect=ValueError("empty file")),
        ):
            with self.assertRaisesRegex(ValueError, "empty file"):
                PEImage(Path("bad.exe"))

        fake_file.close.assert_called_once_with()

    def test_closes_map_and_file_when_header_parse_fails(self) -> None:
        fake_file = MagicMock()
        fake_map = MagicMock()
        fake_map.__len__.return_value = 0
        with (
            patch.object(Path, "open", return_value=fake_file),
            patch("genshinre.pe.mmap.mmap", return_value=fake_map),
        ):
            with self.assertRaisesRegex(ValueError, "not a PE image"):
                PEImage(Path("bad.exe"))

        fake_map.close.assert_called_once_with()
        fake_file.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
