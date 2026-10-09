# Client Dungeon-config candidate

Status: **PARTIAL**. The exact 7.1 Windows client contains a 67-field config
candidate with a native reader. The drop-root interpretation remains
**HIGH_CONFIDENCE**, pending a native asset row and a consumer/loader binding.
This trace does not resolve any of the 140 missing resource roots.

## Target and evidence

The source example is talent Dungeon **4434**: scene `40764`, level gate `25`,
reward preview `25220`, resin cost `20`, and source key
`IAOMJCLOIEL = 82162700`. That root is absent from the pinned resource DropTable.
These are observations from `AstaPS-Resource@b0f3a279`; they are not values read
from a native client asset.

The canonical metadata field `165131` names `IAOMJCLOIEL`, owned by
`LGLHLMDKIEO` (type definition `33015`). Multiple exact obfuscated keys shared
with DungeonExcelConfigData support this owner candidate. Metadata exposes
67 fields and reader method `261095`, `GMENPOPMKAA(FNIAHJGHFAK)`, at RVA
`0x12CA3BA0`. Metadata offsets are blank. A sequential Windows IL2CPP layout
candidate places this field at `0xE8`; all 67 candidate displacement/width pairs
occur as stores in the reader. This corroborates the layout as a set, without
proving each field-to-store association. Nested reader code reuses RBX for
other objects; its complete store set must not be treated as an offset table.

| Native observation | Evidence |
| --- | --- |
| Optional 4-byte read | `0x12CA5389`: test lower presence mask with `0x2000` (bit 13); absent branch goes to wrapper initialization |
| Wire transform | `0x12CA53CA..53CF`: `uint32_le XOR 0x2DBB0C2F` |
| Reader advances | `0x12CA53C7`: add 4 to the cursor |
| Owner restored | `0x12CA53D3`: reload RBX from the saved owner at `[rbp+0x50]` |
| Memory wrapping | `0x12CA53E7`: call `EEOPHKIFFPL.GDAAEEHCAMH` at `0xBB16020` |
| 4-byte object store | `0x12CA53EF`: move wrapped result to `[rbx+0xE8]` |
| Scalar storage | `EEOPHKIFFPL` (type `28775`) has one `uint32` field, `CBOMLBFIPJM` |
| Native method pointer | `.rdata` holder `0x2A6EAC8` contains VA `0x152CA3BA0` |

The sole pointer holder is the canonical method-pointer-table entry
(`0x2870B90 + 261095 * 8`), so it supplies pointer identity rather than a
config loader or independent runtime registration.

The wrapper encode/decode routines use byte permutation tables and a runtime
XOR key. Reading the stored four bytes directly does not recover the source
integer. The wire XOR constant describes one field reader; it is not a
probability, drop weight, quantity or file-level decryption key. The native
read/store observations are exact; associating this store with the metadata
field and interpreting the value as a drop-root ID remain candidate bindings.

## Loading and reward boundary

The bounded static scans found no direct `E8 rel32` call to the reader or its
constructor, and no supported RIP-relative code xref to the sole aligned data
holder pointing at the reader. Indirect dispatch, computed addressing and
runtime registration remain outside those scans. The zero counts do not prove
the config is unused or absent. A config filename search did not supply an
asset binding; no guessed filename is published as an established path.

Still unresolved:

- AssetIndex/native bundle binding and the actual Dungeon 4434 serialized row.
- Loader/dispatch ownership and a consumer interpreting the candidate ID.
- Claim request/response binding and live reward observations.
- Missing server DropTable/DropSubTable rows, quantities and native rates.

## Reproduction

[client-config-candidate.json](client-config-candidate.json) includes exact
sample SHA-256 values, canonical CSV Git blob hashes, source pin, field records,
short native instruction excerpts, pointer and direct-call scan scopes.
No executable, metadata binary or bundle is committed.

```sh
python -m pip install capstone==5.0.9 zstandard
bash scripts/fetch-7.1-samples.sh --output inputs/7.1.0-global --python python
python scripts/collect-7.1-client-dungeon-config.py \
  --samples inputs/7.1.0-global --resource-root /path/to/AstaPS-Resource --check
```

The collector rejects mismatched client samples and resource blobs, checks the
native instruction anchors and layout store coverage, and compares the complete
regenerated snapshot. Capstone's distribution reports `5.0.9`; its binding's
internal version string reports `5.0.7`, both recorded separately.

The native trace complements the
[resource graph](../../../analyses/progression/economy/7.1-domain-drop-links.json)
and [economy status](../../../analyses/progression/economy/7.1-native-drop-economy.md).
