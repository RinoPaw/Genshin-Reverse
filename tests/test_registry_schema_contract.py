from __future__ import annotations

import unittest

from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.registryxrefpublish import COLUMNS as XREF_PUBLISH_COLUMNS


class RegistrySchemaContractTests(unittest.TestCase):
    def test_xref_publisher_matches_canonical_registry_schema(self) -> None:
        self.assertEqual(CANONICAL_REGISTRY_COLUMNS, XREF_PUBLISH_COLUMNS)


if __name__ == "__main__":
    unittest.main()
