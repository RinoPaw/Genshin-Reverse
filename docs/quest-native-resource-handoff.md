# Quest native-resource research handoff

Checkpoint: 2026-10-06 18:28 +08:00

This is the authoritative resumable handoff for the current Quest investigation.
It supersedes earlier notes in this file where they conflict with the conclusions below.

## Working branch / CI

- Repository: `RinoPaw/Genshin-Reverse`
- Branch: `probe/quest-blb3-binoutput`
- Current head: `0b5f86392410ad67694907e5594f812daca033ff`
- Head message: `ci: verify legacy QuestExcel via 3.0 UserAssembly`
- Required CI at this checkpoint:
  - total CI #1082 / run `37450023931`: SUCCESS
  - focused `Probe 3.0 legacy QuestExcel binary reader` #4 / run `37450024126`: SUCCESS
- Latest 3.0 artifact:
  - name: `quest-legacy-30`
  - artifact id: `11406805727`
  - digest: `sha256:be844250454ee20083c97103bc49fabd95aa0d0198340eeedb834b9ef23bdaca`

Durable Quest analysis:
- `versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`
- `versions/7.1.0-global/windows-x64/analyses/quest-extraction/representative-comparison.json`

Do not restart the old XMF/ctable/block-order guessing work.

---

## Executive state

Issue #8 is now split into three resource generations/layers:

1. **Current 7.1 runtime MainQuest/BinOutput path** — essentially solved for representative fields.
2. **Current 7.1 MainQuestExcel source table** — row type is now bound to `GPCFGOEJFJK`; schema relationship to runtime AFIO is strongly constrained.
3. **Legacy `QuestExcelConfigData` asset** — exact 7.1 asset extraction is solved, but its legacy table/row decoder is still unresolved. Historical 3.0 now provides a direct named decoder anchor.

AstaPS's current `QuestExcelConfigData.json` remains classified as a mixed legacy/synthetic resource, not an exact 7.1 native dump.

---

## 1. Exact 7.1 legacy QuestExcel asset — extraction CONFIRMED

Exact chain:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
  -> MiHoYo 40-bit name hash 0x3B87AE8396
  -> design index 31049741.blk
  -> Raw design-index object MiHoYoBinData/0000006f.dat
  -> sub_asset_id 178
  -> block_id 25539185
  -> group_id 0
  -> AssetBundles/blocks/00/25539185.blk
  -> Raw MiHoYoBinData/3b87ae83.dat
  -> payload
```

Pinned values:

- raw object: 2,824,192 bytes
- MiHoYoBinData payload: 2,824,188 bytes
- first four payload bytes: `b1 3a 23 40` = `0x40233AB1` little-endian

### Important framing correction

Earlier exploratory notes treated `b1 3a` as unsigned varint `7473`, then interpreted
the next byte `0x23` as a possible 35-byte presence bitmap length.

That is **not a promoted framing result**.

The 7.0 peer reverse work and current 7.1 Quest Excel loaders show the native ExcelBin
family uses:

```text
u32 encoded_count
row[0]
row[1]
...
```

with build/type-specific arithmetic on the u32 count.

Therefore:

- `7473` remains only an observed alternative interpretation of the prefix bytes;
- do not use it as a row count;
- do not use `0x23` as a proven bitmap length;
- the legacy `QuestExcelConfigData` count transform still needs its own exact loader.

A scan for a one-step `add/xor` transform from `0x40233AB1` to plausible historic row
counts produced no direct hit. The legacy loader is either multi-step, no longer directly
referenced in 7.1, or uses a different parser generation.

---

## 2. Current 7.1 MainQuest binary runtime path — CONFIRMED

### Full vs brief indexes

Do not conflate them.

```text
Data/_BinOutput/IndexDic/MainQuestIndex
  literal index 64807
  string slot RVA 0x5A57B98
  -> static ODJJEFFIPFA +0x31350
  -> full MainQuest config
  -> AFIOOHMJHDM

Data/_BinOutput/IndexDic/MainQuestBriefIndex
  literal index 64809
  string slot RVA 0x5A57BA8
  -> static ODJJEFFIPFA +0x312E0
  -> brief config
  -> FNJLMNMEKLN
```

The index wire format is exact:

```text
encoded_count : u32
count = (encoded_count XOR 0x5785D208) + 0x0A34766E

repeat count:
    encoded_id     : u32
    encoded_handle : u64

    id     = encoded_id XOR 0x92C938B5
    handle = encoded_handle + 0x2B6567EA
```

Both current indexes decode to 4,417 unique main-quest IDs and consume their payloads exactly.

### Full quest 351 path

```text
mainId 351
 -> MainQuestIndex
 -> handle 0x14B93FDA285D0829
 -> Data/_BinOutput/Quest/351
 -> block 24230448
 -> payload 920 bytes
 -> AFIOOHMJHDM.GMENPOPMKAA @ 0x10409D40
 -> LAIMPNDEFCL[8]
```

Ordinary-row count at payload offset `0x3B`:

```text
count = raw_u32 XOR 0xA74F0ACB = 8
```

Exact row starts:

```text
35100  0x03F
35101  0x0A9
35102  0x136
35103  0x196
35104  0x1F8
35105  0x24F
35106  0x2B2
35107  0x327
row-array end 0x384
```

The remaining AFIO outer fields consume through `0x398`; there are zero unexplained trailing bytes.

---

## 3. Current ordinary Quest row `LAIMPNDEFCL` — solved core fields

Type:

- `LAIMPNDEFCL`
- typeDefinition 17589
- scalar reader: `GMENPOPMKAA(FNIAHJGHFAK) @ 0x9C15DF0`

Exact semantic mappings:

```text
+0x10 = failExec
+0x18 = failCond
+0x20 = finishCond
+0x58 = finishExec

+0x70 = mainId
+0x74 = subId / quest config id
+0xA8 = order
```

Element families:

```text
KIMCPAKMJMH[]  = QuestExec entries
JPGNLOPMNHN[]  = QUEST_CONTENT_* condition entries
```

Current count transforms:

```text
QuestExec[]:
  count = raw_u32 + 0xB0F7C9F4

QuestContent[]:
  count = (raw_u32 + 0x9278C6C1) XOR 0x415C14AA
```

Representative nested families already identified:

```text
HINHMGGLBBM : OOPFBIEAILL      guide family
BIHKOLLEDPE : KPHLFFOELCG      guideHint family
KIILAIEPKIA : KAABNOHKKEP      banType family
MDLABCMFLMH : ShowQuestGuideType
```

Do not reopen the four finish/fail array mappings without contradictory exact evidence.

---

## 4. Direct native 351 semantics — CONFIRMED

Exact binary decode:

```text
35100.finishCond
  FINISH_PLOT [35100,0]
  TRIGGER_FIRE [1053,0]

35101.failCond
  QUEST_CONTENT_TEAM_DEAD [0,0]

35101.failExec
  QUEST_EXEC_ROLLBACK_QUEST ["35100"]

35101.finishCond
  TRIGGER_FIRE [1100,0]

35102.finishCond
  TRIGGER_FIRE [1017,0]

35103.finishCond
  TRIGGER_FIRE [1016,0]

35104.finishCond
  FINISH_PLOT [35104,0]

35105.finishCond
  TRIGGER_FIRE [1016,0]

35106.finishExec
  LOCK_POINT ["3","1720"]

35106.finishCond
  UNLOCK_TRANS_POINT [3,6]

35107.finishExec
  REFRESH_GROUP_SUITE ["3","133003429,1"]

35107.finishCond
  TRIGGER_FIRE [1101,0]
```

The string parameter `"35100"` is decoded from native encoded bytes; it is not copied
from public JSON.

This validates same-version `BinOutput/Quest/351.json` for these tested runtime fields.

Representative full payloads for main quests 375, 376 and 388 have also been exported for
cross-checking.

---

## 5. Current 7.1 MainQuestExcel row type — NEW CONFIRMED BINDING

This is the most important update after the previous handoff.

Current path:

```text
Data/_ExcelBinOutput/MainQuestExcelConfigData
 -> HBGNNDLNDMA.GMENPOPMKAA(FNIAHJGHFAK) @ 0xF955AF0
 -> row type slot 0x57E31B8
```

The same row type slot `0x57E31B8` is referenced by:

```text
GPCFGOEJFJK.CDJEHCCCFME @ 0xCABAC90
```

and the GPC binary row reader is:

```text
GPCFGOEJFJK.GMENPOPMKAA(FNIAHJGHFAK) @ 0xCAB9080
typeDefinition 82662
36 fields
```

Therefore `GPCFGOEJFJK` is no longer merely a speculative Quest-shaped peer:
it is the strongest exact binding for the **current 7.1 MainQuestExcel row type**.

The current MainQuestExcel container:

```text
HBGNNDLNDMA
  field PAAGPEHCJFI : generic collection
  field PBLMHNBIAJL : bool
```

Current loader head uses the standard ExcelBin family shape: encoded u32 count, allocation,
then row construction/deserialization.

### GPC relation to runtime AFIO/FNJ

GPC shares:

- 31 field names with `AFIOOHMJHDM`;
- 15 field names with `FNJLMNMEKLN`.

GPC-only relative to AFIO is only five scalar fields:

```text
BBHPAJDLCOK : uint32
DBCBJAEKPAN : bool
JMJKAOLFPCG : uint32
KLMMPLDJAHJ : uint32
OLDEPAOFOKH : uint32
```

AFIO has runtime-only/additional container fields such as the ordinary `LAIMPNDEFCL[]`
array and other collections.

This makes the current relation approximately:

```text
MainQuestExcelConfigData
 -> GPCFGOEJFJK source row
 -> current runtime projection / expansion
 -> AFIOOHMJHDM
 -> LAIMPNDEFCL[]
```

The exact conversion method between GPC and AFIO still needs a final direct method-level
binding, but the type-slot and field-overlap evidence is now strong.

### Consequence for legacy prerequisite fields

The current GPC row does **not** expose a RandomQuest-style named/object-array family for:

```text
acceptCond
acceptCondComb
beginExec
```

Its five GPC-only fields relative to AFIO are scalars only.

This strongly supports the conclusion that the historical ordinary-Quest prerequisite
schema is not part of the current 7.1 MainQuestExcel row in the old form.

Do not project `RandomQuestExcelConfig` onto GPC or LAIMPNDEFCL.

---

## 6. Named RandomQuest control — keep separate

`RandomQuestExcelConfig` remains useful as a named schema control.

Current 7.1 named fields include:

```text
_beginExec
_acceptCond
_acceptCondComb
_failExec
_failCond
_finishExec
_finishCond
_finishCondComb
_failCondComb
_mainId
_subId
_order
...
```

It is a different row type.

The source-row metadata ranking correctly puts it first because the names survive; that
does not make it the ordinary/story Quest row.

---

## 7. Legacy QuestExcel historical trace — NEW direction

The current 7.1 executable no longer exposes a clear literal
`Data/_ExcelBinOutput/QuestExcelConfigData`.

To recover the legacy asset schema, the investigation moved backward through exact official
client samples.

### 6.7 control

Recovered protected literals include:

```text
Data/_ExcelBinOutput/MainQuestExcelConfigData
Data/_ExcelBinOutput/RandomQuestExcelConfigData
Data/_ExcelBinOutput/RandomMainQuestExcelConfigData
acceptCond
acceptCondComb
beginExec
```

but no direct recovered `QuestExcelConfigData` path binding.

The surviving prerequisite-name literals alone are not proof of ordinary Quest ownership,
because RandomQuest still uses them.

### 4.2 control

Exact 4.2 UserAssembly/global-metadata samples were obtained, but the existing literal
recovery logic encounters a newer/unsupported metadata-obfuscation generation for that
sample. Raw-name scans did not provide a decisive legacy QuestExcel binding.

Do not spend more time forcing the current stringliteral decoder onto 4.2 unless needed;
3.0 is currently the cleaner historical anchor.

### 3.0 exact historical anchor — SUCCESS

Official 3.0 ScatteredFiles sample:

```text
UserAssembly.dll
  size   177601560
  sha256 b368b8959442f351143d16eb67d514520064897d1eeb37e0d3f544688bd4510b

global-metadata.dat
  size   49356392
  sha256 efd5a35bed23de3f1444d40ebf4eaa1dfb338c84d7a168a0264678f94cca5a2a
```

Direct named functions:

```text
QuestExcelConfigLoader.FILE_LOCATION
  RVA 0x10FC970

QuestExcelConfigLoader.FromBinary(ByteArray)
  RVA 0x10FD580

QuestExcelConfig.FromBinary(ByteArray)
  RVA 0x3AF9E10
```

The exact 3.0 row reader accesses the known legacy layout containing:

```text
+0x10 subId
+0x14 mainId
+0x18 order
+0x38 acceptCondComb
+0x40 acceptCond
+0x48 finishCondComb
+0x50 finishCond
+0x58 failCondComb
+0x60 failCond
+0x68 guide
+0x70 showGuide
+0x74 finishParent
+0x75 failParent
+0x78 failParentShow
+0x7C isRewind
+0x80 finishExec
+0x88 failExec
+0x90 beginExec
+0x98 exclusiveNpcList
...
```

Important evidence level:

- these offsets are the known 3.0 legacy class layout used by the probe;
- the exact 3.0 `QuestExcelConfig.FromBinary` machine code accesses those offsets;
- this is a strong historical control;
- do **not** copy its constants/field order into 7.1 without proving binary-format continuity.

This is currently the shortest path to reconstruct the legacy QuestExcel wire schema.

---

## 8. AstaPS / public-resource root cause status

### AstaPS QuestExcel

Current AstaPS `QuestExcelConfigData.json`:

- 33,217 rows;
- 35100..35107 contain the old synthetic/legacy `QUEST_COND_STATE_EQUAL` chain;
- upstream PR #9 appended 7,956 missing rows from BinOutput and synthesized prerequisites for
  newly appended rows because BinOutput lacks `acceptCond/beginExec`;
- existing 351 rows predate that augmentation.

Classification remains:

**HIGH_CONFIDENCE legacy resource / materialization contamination.**

### Same-version BinOutput

Same-version Dimbreath and AstaPS `BinOutput/Quest/351.json` agree with the directly decoded
native 351 payload on tested core fields.

### Dimbreath public QuestExcel

Public field labels are schema-misaligned. Examples already established:

- guide-shaped value published under `acceptCondComb`;
- `failParent` carrying the value matching `descTextMapHash`;
- `failCondComb = QUEST_HIDDEN` where the value belongs to show-type semantics.

Use it only as a byte/value cross-check, not as a field-name oracle.

---

## 9. What remains for #8

The runtime side is nearly closed. The remaining decisive question is the **legacy
`QuestExcelConfigData` asset** shipped in 7.1.

Need to establish:

1. exact legacy table count transform for the 2,824,188-byte payload;
2. exact legacy row framing/deserializer;
3. decode only the high-value fields first:
   - `subId`
   - `mainId`
   - `acceptCond`
   - `acceptCondComb`
   - `beginExec`
4. locate 35100..35107 in that exact 7.1 legacy payload;
5. determine whether the old prerequisite chain is physically present in the shipped legacy
   asset or was introduced by later public/downstream materialization;
6. verify complete consumption or an equally strong structural invariant.

Only after this should issue #8 be promoted to CONFIRMED and AstaPS resources be repaired.

---

## 10. Resume here — shortest next path

1. Stay on `probe/quest-blb3-binoutput`; refetch current head before editing.
2. Use the successful 3.0 exact named anchor:
   - loader `0x10FD580`
   - row reader `0x3AF9E10`
3. Recover the **3.0 table count transform and row mask/field transforms** mechanically from
   those methods.
4. Establish a format fingerprint for the old `QuestExcelConfigData` row:
   - count width/op sequence;
   - row mask width/op sequence;
   - transforms for `subId/mainId`;
   - array readers for `acceptCond/beginExec`;
   - combiner scalar.
5. Search 7.1 for that **instruction/format family**, not for the old names.
6. If no 7.1 loader exists, test whether the exact 7.1 legacy asset still matches the 3.0
   wire fingerprint by decoding a small prefix and requiring structural validity.
7. If it matches, decode the 351 rows and classify the prerequisite chain.
8. If it does not match, locate the version transition between 3.0 and 7.1; 4.2/6.7 are
   secondary controls only.

Do not broaden back into unrelated Quest fields until these five legacy fields are settled.

---

## 11. Known dead ends / corrections

Do not repeat:

- `7473` as a confirmed QuestExcel row count — superseded.
- `0x23` as a confirmed 35-byte row bitmap — superseded.
- simple `u32 + K` / `u32 XOR K` matching from 7.1 legacy payload head to public row counts
  as proof of the loader — no direct hit.
- RandomQuest layout projected onto ordinary Quest.
- historical 351 prerequisite edges used as current runtime truth.
- direct callers of `QuestCond.FromBinary(reader, kind_0x1D) @ 0x115828F0` as the main route.
- seven anonymous arrays mapped ordinally to the historical seven Quest lists.
- asset-index trailing words interpreted as byte offset/size.
- primary/external AssetIndex confusion.
- `+0x312E0` treated as the full MainQuest index; it is the brief index. Full is `+0x31350`.
- treating GPC as merely an unbound peer; current row-slot evidence now binds it to
  `MainQuestExcelConfigData`.

---

## #9 separate track

Keep #9 separate from #8.

Exact 7.1 fresh-born anchor remains:

```text
DoSetPlayerBornDataNotify
CmdId          22899
client type    ONKOPMILDMF
handler owner  LLCGIEDMIIG
handler        MACAMCMOKOL(ONKOPMILDMF)
RVA            0x0C227790
method index   322028
```

The direct native 351 evidence now proves:

```text
35101 TEAM_DEAD -> ROLLBACK_QUEST 35100
```

but that is still a gameplay rewind mechanism and must not be used by itself to explain the
persistent Return-to-quest-point UI state.

---

## Repository / CI rules

- Keep exact reverse evidence and durable conclusions in `Genshin-Reverse`.
- Probe workflows may remain on this branch while investigation is active.
- Do not run heavyweight CI after every exploratory edit.
- Full CI is mandatory before asking the user to test and before upstream submission.
- User has asked the assistant to watch CI directly; do not ask the user to report CI status.
- If user testing becomes necessary, provide one complete copy-paste command including
  remote fetch, branch switch, dependency/build steps, and test/run command.
