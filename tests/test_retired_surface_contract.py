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

    def test_retired_surfaces_stay_removed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        retired = (
            "tools/inspect_method_context_71.py",
            "tools/inspect_protocol_type_shape_71.py",
            "tools/scan_owner_rpc_submit_layout_71.py",
            "tools/scan_protocol_method_callers_71.py",
            "tools/trace_protocol_delegate_slots_71.py",
            "tools/fetch_sophon_targets.py",
            ".github/workflows/probe-cmd186-external-consumer.yml",
            ".github/workflows/publish-7.1-candidate-graph.yml",
            ".github/workflows/publish-7.1-registry-xrefs.yml",
            ".github/workflows/recover-7.1-registry-slot-xrefs.yml",
            ".github/workflows/recover-7.1-registry-type-slots.yml",
            "genshinre/getcmdidgraph.py",
            "genshinre/graphdiag.py",
            "genshinre/paramprobe.py",
            "genshinre/proto_shape.py",
            "tests/test_getcmdidgraph.py",
            "tests/test_graphdiag.py",
            "tests/test_paramprobe.py",
            "tests/test_proto_shape.py",
            "versions/7.1.0-global/windows-x64/registry/getcmdid-candidate-graph.csv",
            "versions/7.1.0-global/windows-x64/registry/getcmdid-candidate-graph.summary.json",
            "genshinre/metareg.py",
            "genshinre/metausage.py",
            "genshinre/usage.py",
            "genshinre/usagejoin.py",
            "genshinre/usagesource.py",
            "genshinre/usagesourcediag.py",
            "genshinre/usageanchordiag.py",
            "genshinre/initializerflowdiag.py",
            "genshinre/registrycorridordiag.py",
            "genshinre/registryreport.py",
            "genshinre/registryselect.py",
            "tests/test_metareg.py",
            "tests/test_metausage.py",
            "tests/test_usage.py",
            "tests/test_usagejoin.py",
            "tests/test_usagesource.py",
            "tests/test_registryreport.py",
            "tests/test_registryselect.py",
            "versions/7.1.0-global/windows-x64/registry/metadata-registration-probe.json",
            "versions/7.1.0-global/windows-x64/registry/metadata-usage-slots.csv",
            "versions/7.1.0-global/windows-x64/registry/metadata-usage-slots.summary.json",
            "versions/7.1.0-global/windows-x64/registry/registry-layout-probe.json",
        )
        for relative in retired:
            with self.subTest(path=relative):
                self.assertFalse((root / relative).exists())


if __name__ == "__main__":
    unittest.main()
