# Registry artifacts

This directory contains protocol-registry artifacts for the exact 7.1 sample in `../hashes.json`.

## Canonical identity registry

The maintained 7.1 identity dataset is:

- `registry.csv`: complete 4,896-row primary query surface;
- `registry.summary.json`: closure statistics, control anchors and publication status;
- `registry-type-slots.csv`: exact constructor/type slots and load/store provenance;
- `registry-slot-xrefs.csv`: dominant current-client relationships between GetCmdId candidate types and verified slots.

The publisher requires a strict one-to-one registry-slot / type-definition / CmdId mapping across all 4,896 rows. Direction and semantic names are independent evidence layers; unresolved semantic fields do not invalidate the closed numeric/type identity registry.

Current canonical columns:

```text
index,cmd_id,type_name,type_definition_index,direction,direction_status,semantic_name,type_slot_rva,get_cmd_id_rva,get_cmd_id_method,load_rva,store_rva,xref_count,xref_method_count,status,evidence
```

Routine lookups use:

```bash
genshinre query-registry registry.csv --cmd-id 186
genshinre query-registry registry.csv --type NLOMEGMJDGJ
genshinre query-registry registry.csv --type-definition-index 61556
genshinre query-registry registry.csv --index 48
```

## Maintained regeneration path

`.github/workflows/generate-7.1-data.yml` owns the canonical exact-sample chain. Registry generation runs in one ordered transaction after metadata/GetCmdId regeneration:

```text
pinned GenshinImpact.exe
+ regenerated methods/GetCmdId candidates
→ genshinre.registryslots
→ genshinre.registryslotxref
→ genshinre.registryxrefpublish
→ strict 4,896-row registry
```

The three former registry-specific Actions were retired after this path stabilized. The package modules remain directly invokable when focused debugging is useful.

Example relationship recovery:

```bash
python -m genshinre.registryslotxref \
  /path/to/GenshinImpact.exe \
  ../metadata/methods.csv \
  getcmdid-candidates.csv \
  registry-type-slots.csv \
  registry-slot-xrefs.csv \
  --summary registry-slot-xrefs.summary.json
```

The publisher then consumes `registry-slot-xrefs.csv`, `registry-type-slots.csv`, and evidence-gated `../proto/known-opcodes.csv`.

## GetCmdId candidates

`getcmdid-candidates.csv` and its summary are the maintained conservative constant-return scan. They are an input to registry-slot relationship recovery and may contain duplicate numeric candidates before slot evidence resolves identity.

The former structural GetCmdId candidate graph was a pre-closure research surface. Once the strict 4,896-row registry became canonical it no longer added a maintained identity layer, so its workflow, generated graph files, package module and tests were retired. Git history preserves that experiment.

## Semantic controls

`control-set.csv` is an imported AstaPS comparison surface. Membership does not establish current-client semantic identity.

Evidence-gated current-target semantic mappings live separately at `../proto/known-opcodes.csv`.

Keep these roles separate:

- `registry/control-set.csv` — broad external/server comparison data;
- `proto/known-opcodes.csv` — target-client semantic names that passed the repository evidence gate.

## Retired recovery paths

Older metadata-usage/type convergence, type-cache naming, native-array hypotheses and other pre-closure experiments are retained in Git history rather than as alternate live registry paths.

The maintained identity rule is:

```text
verified constructor/type slots
+ current GetCmdId candidates
+ dominant registry-slot xrefs
→ strict 4,896-row canonical registry
```

Do not add a second publication path for the same identity layer. If this chain needs to change, update the canonical generator and its validation contract together.
