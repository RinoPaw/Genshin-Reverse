# Client Dungeon-config candidate

Status: **PARTIAL**. The exact 7.1 Windows client contains a 67-field config
candidate with a native reader. The drop-root interpretation remains
**HIGH_CONFIDENCE**, pending a complete native asset row decode and a consumer/loader binding.
The native Dungeon payload is now extracted and identified in the design index.
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
| Optional 4-byte read | `0x12CA5389`: test lower transformed presence mask with `0x2000` (bit 13); absent branch goes to wrapper initialization |
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

The target tests bit 13 of a **transformed** mask:
`((uint64_le + 0x85B5FF59) mod 2^64) XOR 0xD3D96C23`. Its present branch
requires transformed bit 13 to be set; before the XOR that bit is clear. The
initial mask read, XOR and saved-mask instructions are now included in the
snapshot. A bare bit number must not be applied directly to serialized bytes.

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
the config is unused or absent. The earlier executable filename search did not supply an asset binding.
The design AssetIndex path-hash lookup has now located and extracted the
Dungeon payload; that resource lookup does not establish the runtime loader.

Still unresolved:

- Complete row schema/framing and the actual Dungeon 4434 decoded row.
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

## Exact resource lookup and drop-table search

[asset-path-probes.json](asset-path-probes.json) records a fully consumed design
AssetIndex export: 247,073 name records and 536 asset-to-block references.
Official Sophon block `00/31049741.blk` has manifest MD5
`a390222739d22aafb110019d10bff7e8`; its `MiHoYoBinData/0000006f.dat` Raw export
has SHA-256 `fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712`.
The corresponding path hashes resolve all five controls to block `00/25539185.blk`
(manifest MD5 `8ce0bb0ac5ec42315f0f98d52e5d7c73`, sub-asset group 178).

| Candidate path under `Data/_ExcelBinOutput/` | Raw export | Payload bytes |
| --- | --- | ---: |
| DungeonExcelConfigData | `c39aec1e.dat` | 426,891 |
| DailyDungeonConfigData | `b898093c.dat` | 7,684 |
| DungeonEntryExcelConfigData | `73c14e38.dat` | 15,779 |
| RewardPreviewExcelConfigData | `11276dc3.dat` | 288,131 |
| QuestExcelConfigData (control) | `3b87ae83.dat` | 2,824,188 |

All five assets were actually Raw-exported and their payloads unwrapped with
length/padding validation. The QuestExcel payload hash matches the independently
published exact Quest extraction evidence. Dungeon payload SHA-256:
`9d3d2a3718288004a5fc6e6dd57443ded35d0a0a45cbcdb1b767bd0eadb36834`.
Path-hash membership is not by itself a semantic schema or loader proof.

The finite drop search tested eleven table-name candidates under six prefixes
(66 exact path hashes, all **HASH_ABSENT**). The full list is in the JSON; it
includes DropTable/DropSubTable/DropMaterial Excel names, shorter names and
DungeonDrop variants. Positive controls distinguish a usable design index from
an empty/broken extraction. This rules out the listed identities in this index;
it does **not** rule out alternative names, another index, transformed/embedded
data or server-only tables.

A source-selected byte search of the Dungeon payload found `82162700 XOR
0x2DBB0C2F` once at payload offset 215,120, and the corresponding candidate for
`82165000` once at 215,787. Both are **CANDIDATE_BYTE_MATCH** only. Without full
row framing they establish neither Dungeon 4434/4437 ownership nor the field's
semantic meaning. Do not promote these into native decoded JSON.

A local displacement/nearby-wrapper-call probe also produced unrelated owners,
including `MusicEditorTimeLineComponent.SetupBeatDivisionDropDown`: its method
starts at `0xB724D20`, has an apparent `[rsi+0xE8]` load at `0xB724EBB` and a
nearby wrapper-decode call. Therefore offset plus wrapper identity cannot bind
the Dungeon field. No confirmed Dungeon consumer or claim path was recovered.

Reproduce with the pinned `EIHRTeam/AnimeStudio` Linux CLI archive SHA-256
`12e2dfb2ab35880eda4274fcd393091d47e204d4b6e4b5838421fa3b4d1720a1`
(release `v1.0.0-CI`) and .NET runtime 10.0.0. Reconstruct the two blocks from
the pinned `NativeProfile` Sophon manifest, as the Quest extractor does, then:

```sh
dotnet /path/to/AnimeStudio.CLI.dll inputs/7.1.0-global/31049741.blk \
  inputs/7.1.0-global/design-index-export --game GI --types MiHoYoBinData \
  --export_type Raw --logger_flags Error
dotnet /path/to/AnimeStudio.CLI.dll inputs/7.1.0-global/25539185.blk \
  inputs/7.1.0-global/excel-export --game GI --types MiHoYoBinData \
  --export_type Raw --logger_flags Error
python scripts/collect-7.1-dungeon-assets.py --samples inputs/7.1.0-global --check
genshinre query-assets inputs/7.1.0-global/design-index-export/MiHoYoBinData/0000006f.dat \
  Data/_ExcelBinOutput/DungeonExcelConfigData \
  Data/_ExcelBinOutput/DropTableExcelConfigData
```

The reusable path-hash query is in `genshinre.assetindex`, beside the index
parser used by Quest extraction. It explicitly distinguishes absent hashes,
ambiguous names, incomplete references and resolved locations. The raw client
assets remain local inputs and are not redistributed.

Next evidence gates: fully decode the Dungeon table without trailing bytes;
validate the candidate root field on actual rows; bind a typed consumer and
lookup target. Only a recovered drop table plus its selection algorithm could
close quantities/probabilities. No missing-root status is changed by this probe.
