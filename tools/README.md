# Tools directory policy

`tools/` contains narrow helpers and investigation-oriented scripts. It is not the primary user-facing command surface of Genshin-Reverse.

For reusable repository functionality, prefer this order:

1. implement the operation in `genshinre/` with unit tests;
2. expose it through the `genshinre` CLI when it is generally useful;
3. use `scripts/` for maintained multi-step orchestration;
4. use `tools/` only when the operation is intentionally narrow, sample-specific, exploratory, or an external-resource helper that does not belong in the package API.

## Maintained infrastructure helper

`fetch_sophon_targets.py` reconstructs selected files from an explicitly supplied Sophon manifest/chunk prefix and verifies requested hashes. The pinned 7.1 entry points are `scripts/fetch-7.1-samples.sh` and `.ps1`; maintained workflows should call those wrappers rather than embedding manifest identities in YAML.

## Research helpers

The remaining inspect/scan/trace/decode scripts are research scaffolding for specific native-analysis questions. They may use fixed RVAs, exact type identities, historical samples, or experiment-specific output shapes.

Decoded metadata consumer lookup is maintained package functionality now: use `genshinre query-methods --parameter-type ...` for direct parameter searches and `genshinre protocol-query` for joined signature-reference evidence. The old standalone decoded consumer helper was retired.

`decode_protocol_handler_parameters_71.py` remains intentionally separate because it independently decodes exact-sample parameter records back to runtime type indices and applies known handler controls. That raw-record cross-check is a different evidence layer from querying the already decoded metadata table.

Historical registry-order, TypeDefinition-order, scene-cluster and response-neighborhood comparators were also retired after their conclusions and rejection boundaries were preserved in the case-study/analysis records. Git history remains the reproduction source if one of those discarded hypotheses needs to be revisited under a changed premise.

Do not promote a result produced by one of these scripts into canonical protocol data solely because the script completed successfully. Promotion still follows `docs/analysis-contract.md` and the relevant artifact publication gate.

When a research algorithm becomes broadly reusable, move the implementation into `genshinre/`, add tests, and reduce the tool/workflow to thin orchestration or retire it after its evidence is preserved.

## Retired duplicate/general helpers

The following old standalone helpers were removed after their capability moved to the maintained command surface or native decoder:

- `fingerprint_sample.py` → `genshinre fingerprint` (including sample format detection);
- `protobuf_wire.py` → `genshinre wire`;
- `query_registry.py` → `genshinre query-registry`;
- `decode_method_parameters_71.py` → native `genshinre.mhy71` parameter decoding. Its three preserved handler-parameter checks now live in `versions/7.1.0-global/windows-x64/metadata/anchors.json` and are enforced by the normal metadata-anchor verification path;
- `find_protocol_parameter_consumers_71.py` → `genshinre query-methods` / `genshinre protocol-query`;
- packet-specific UnlockTransPoint capture analyzers → `genshinre correlate-capture`.

The moving HoYoPlay and third-party HoyoDL 7.1 fetchers were also retired. Exact 7.1 maintenance uses the pinned Sophon sample path; a future live-version discovery tool should be named and documented as discovery-only rather than presented as an exact-sample fetch path.
