# Quest native-resource research handoff

Checkpoint: 2026-10-06

This file is the authoritative resumable handoff for the current Quest investigation.
Refetch the branch head before editing because focused probes may still advance it.

## Working branch

- Repository: `RinoPaw/Genshin-Reverse`
- Branch: `probe/quest-blb3-binoutput`
- Last fully green provenance checkpoint:
  - head `10e14fd65923a9504b37a256ecbfc7a4a8dc0036`
  - CI #1150 / run `37480736397`: SUCCESS
  - `Compare native and AstaPS Quest 351 provenance` #2 / run `37480736548`: SUCCESS
  - artifact `quest-351-provenance` id `11420239191`
- A later focused 7.1 subId-transform probe may be running; inspect current branch/runs before resuming.

Durable analysis:
- `versions/7.1.0-global/windows-x64/analyses/quest-extraction/README.md`

## Executive verdict

The **AstaPS Quest 351 prerequisite-chain provenance is CONFIRMED downstream
synthesis/materialization**.

The exact 7.1 legacy `Data/_ExcelBinOutput/QuestExcelConfigData` row wire is still
unresolved. That remaining format problem is independent and no longer blocks the
AstaPS provenance verdict.

Do not revert to the old assumption that exact 7.1 legacy-table decoding is required
before classifying the AstaPS 351 chain.

---

## 1. Current 7.1 runtime Quest path — CONFIRMED

Full current path:

```text
Data/_BinOutput/IndexDic/MainQuestIndex
 -> ODJJEFFIPFA static +0x31350
 -> mainId 351
 -> handle 0x14B93FDA285D0829
 -> Data/_BinOutput/Quest/351
 -> AFIOOHMJHDM
 -> LAIMPNDEFCL[8]
```

Quest 351 payload is 920 bytes and is completely consumed.

Exact current semantics include:

```text
35101.failCond
  QUEST_CONTENT_TEAM_DEAD [0,0]

35101.failExec
  QUEST_EXEC_ROLLBACK_QUEST ["35100"]
```

The ordinary row `LAIMPNDEFCL` carries current finish/fail condition and exec arrays.
No direct old-style ordinary `acceptCond` / `beginExec` slot has been identified.

Current `MainQuestExcelConfigData` is bound to `GPCFGOEJFJK`; its row shape also does
not expose the historical ordinary-Quest prerequisite object-array family.

Keep `RandomQuestExcelConfig` separate. It still has named `_acceptCond`,
`_acceptCondComb`, and `_beginExec`, but it is a different table.

---

## 2. Exact 7.1 legacy QuestExcel asset — extraction CONFIRMED, row wire unresolved

Exact asset chain:

```text
Data/_ExcelBinOutput/QuestExcelConfigData
 -> MiHoYo hash 0x3B87AE8396
 -> design index 31049741.blk
 -> MiHoYoBinData/0000006f.dat
 -> sub_asset_id 178
 -> block_id 25539185
 -> group_id 0
 -> MiHoYoBinData/3b87ae83.dat
```

Pinned values:

```text
raw size       2,824,192
payload size   2,824,188
raw sha256     f068fc7f5dc0a0560ef0b145cdca14ee12910d0a3bc25a6332e2546f37650c87
payload sha256 07ab4816ee1eaa68fefd636b92dcfa923fe58a15731d18de0c0fb26863791fe5
```

Corrections:

- `7473` is only an alternative uvarint interpretation of the leading bytes. Do not call it row count.
- `0x23` is not a proven bitmap length.
- Do not force the 2.8/3.x wire onto 7.1.

Known 7.1 native `subId` anchor observation:

```text
encoded_u32 = subId XOR 0xB1571A55

35104 @ 2056
35100 @ 2128
35107 @ 2188
35101 @ 2270
35106 @ 2351
35105 @ 2433
35103 @ 2519
35102 @ 2599
```

A current devkit-wide schema scan tested 13,411 reader methods / 262 plausible candidates.
No candidate consumed all eight Quest 351 windows exactly. A second pass built 342 plausible
7.1 reader schemas and tested their 32-bit field transforms against all eight observed
`subId` anchors; it found zero 8/8 decoder matches. Treat these results as evidence that
the current model still misses the 7.1 field framing/transform family, not as proof of any
particular field absence.

A JSON-presence correlation probe also exists, but it is not decisive because many
AstaPS fields are always materialized as empty/default values and therefore correlate
spuriously.

---

## 3. Historical native QuestExcel — decisive provenance evidence

### 2.8 official client

Exact historical asset:

```text
raw size      3,830,872
raw sha256    d11516d19a77e38c41f3b88aabc6fb6fe1277a57798633a96bc9da17e1df9877
XOR key       0x98
row count     12,158
full consume  YES
```

Quest 351 still carries historical prerequisites, but the graph is not a simple chain:

```text
35100 <- 35104
35107 <- 35100
35101 <- 35100
35106 <- 35101
35105 <- 35106

35103:
  STATE_EQUAL     35106
  STATE_NOT_EQUAL 35105

35102:
  STATE_EQUAL 35103
  STATE_EQUAL 35105
  OR-style combination
```

### 3.2 official client

```text
raw sha256 891d83000eb3eb7382d7781bff12213b55159e7053c22312857a371fa4243c36
XOR key    0x93
row count  15,818
```

All eight Quest 351 rows decode cleanly with the historical QuestExcel schema.
**None has `acceptCond`.**

### 3.4 official client

```text
raw sha256 c034b6ea8714f04d3c3ea8e31e3a944969ecef4fa804156ff046ffd516beaa64
XOR key    0x95
row count  16,727
```

Again, all eight Quest 351 rows have no `acceptCond`.

Therefore the historical 351 prerequisites were already absent from official client
QuestExcel by 3.2.

### 4.2 control

4.2 still matches the old single-byte-XOR wire family:

```text
raw sha256 dce6d2b614fc2d5ee69e24c826ee8a1505490ca3911a4438d04e81c565ccad1a
XOR key    0x94
row count  21,443
```

Full 351 decode is not necessary for the provenance verdict because 3.2 and 3.4 already
establish removal.

5.0+ no longer matches this old single-byte-XOR family.

---

## 4. Community resource materialization — direct tooling evidence

Pinned repository:
`233-Jerry/Grasscutter-Resources@46d2b65b40f2897edc0c0b3ef235e733e6dde6c4`

Its README explicitly describes QuestExcel as modified/incomplete for 3.0+.

### QuestGC.js

`Tool/QuestGC.js` loads newer quest data and `QuestExcelConfigData_2.8.json`.
For any subquest found in 2.8 it explicitly copies forward:

```text
acceptCond
finishCond
failCond
guide
finishExec
failExec
beginExec
```

This is direct evidence that community resource generation deliberately grafted old
2.8 quest logic onto newer resources.

### MergeQuests.js

`Tool/MergeQuests.js` uses a materialized
`QuestExcelConfigData (3.2).json` as the baseline for old quests and writes merged
`BinOutput/Quest/*.json`.

This explains why public files named `BinOutput/Quest/351.json` may contain old
prerequisite data even though exact official 3.2/3.4 native QuestExcel does not.

Do not use public directory names as proof that a row came directly from the client.

---

## 5. AstaPS initial QuestExcel — synthetic linearization

Initial AstaPS QuestExcel commit:

`8c85a82f37341a422002a0352c89a142c4017e53`
(`Add ExcelBinOutput part 3 of 5`)

Pinned initial resource:

```text
row count  25,261
git blob   a87df6727a01910ac193fcf852ac704d33668c68
sha256     456f85fe1587c67521218e88a1a2f53b631eb78f63fa1fa87f056df558e5bcca
```

Quest 351 contains:

```text
35104 <- [0,3]
35100 <- [35104,3]
35107 <- [35100,3]
35101 <- [35107,3]
35106 <- [35101,3]
35105 <- [35106,3]
35103 <- [35105,3]
35102 <- [35103,3]
```

This is pure previous-row/order linearization.

It differs from exact native 2.8:
- native 2.8 has `35101 <- 35100`, not 35107;
- native 2.8 preserves branch logic for 35103 and 35102.

Therefore AstaPS's chain cannot be classified as an unmodified 2.8 carry-forward.

A full-table audit of the initial 25,261 rows confirms this is systemic:

```text
mainId groups                         3,099
rows with STATE_EQUAL acceptCond     25,261 / 25,261
first rows exactly [0,3]              3,099 / 3,099
non-first exact previous-row [*,3]   21,489 / 22,162
all rows matching linear rule        24,588 / 25,261 = 97.34%
groups fully matching rule            2,759 / 3,099
```

The initial resource is therefore overwhelmingly shaped by a synthetic previous-row
prerequisite convention, with a minority of exceptions/overrides.

The 351 rows are already present in the initial AstaPS resource and remain unchanged
through PR #9.

---

## 6. AstaPS-Resource PR #9 documents the existing heuristic

PR #9 / merge `7465e29b2d58058ab9973187c112abf2717ada03` says:

- 7,956 missing BinOutput subquests were appended;
- BinOutput lacked `acceptCond` / `beginExec`;
- new first rows get `QUEST_COND_STATE_EQUAL [0,3]`;
- each later row gets `QUEST_COND_STATE_EQUAL [previous step,3]`;
- this follows the **"convention of the existing rows"**.

This is the same shape already visible in initial Quest 351.

Important distinction:

- PR #9 did **not** create the 351 chain;
- it documents and reuses the pre-existing synthetic convention.

---

## 7. Provenance verdict

For AstaPS Quest 351:

**CONFIRMED downstream synthetic/materialized prerequisite data.**

Evidence chain:

1. exact native 2.8 contains a more complex historical graph;
2. exact native 3.2 and 3.4 contain no 351 `acceptCond`;
3. community tooling explicitly carries 2.8 quest logic into newer resource generations;
4. AstaPS initial 351 is a simplified order-derived graph, not native 2.8;
5. PR #9 explicitly identifies the same previous-row heuristic as an existing convention.

The exact physical contents of the 7.1 legacy `3b87ae83.dat` rows remain unproven.
Do not claim that 7.1 physically contains or physically lacks 351 `acceptCond` until the
7.1 wire is directly decoded.

That unresolved question no longer blocks the AstaPS resource-provenance verdict.

---

## 8. Product/resource repair direction

Do not blindly delete every `acceptCond` yet.

Before changing AstaPS resources:

1. audit how many initial 25,261 rows use the previous-order synthesis pattern;
2. separate exact historical conditions from generated previous-order conditions where
   possible;
3. determine whether AstaPS runtime still depends on synthetic `acceptCond` for task
   activation;
4. use current 7.1 BinOutput/runtime conditions as the authority for current behavior;
5. repair narrowly first, then generalize only with evidence.

Quest 351 is a strong candidate for removing/replacing the synthetic chain because current
7.1 native runtime behavior is independently decoded.

---

## 9. Independent 7.1 wire-research track

If continuing exact 7.1 legacy decoding:

1. use current native registration / table container evidence;
2. do not search by obsolete 3.x field names alone;
3. use the confirmed `subId` anchors as structural checkpoints;
4. require exact row-boundary consumption across many consecutive rows;
5. require full table consumption or an equally strong invariant before assigning field
   semantics.

Do not use:
- old 3.x row schema by assumption;
- AstaPS JSON field presence as a schema oracle;
- RandomQuest layout as the ordinary Quest layout;
- anonymous array ordinal mapping.

---

## 10. Separate #9 track

Keep the Return-to-quest-point / born-data issue separate.

Current exact anchor:

```text
DoSetPlayerBornDataNotify
CmdId          22899
client type    ONKOPMILDMF
handler owner  LLCGIEDMIIG
handler        MACAMCMOKOL
RVA            0x0C227790
method index   322028
```

`35101 TEAM_DEAD -> ROLLBACK_QUEST 35100` is a gameplay rewind mechanism. It does not,
by itself, explain persistent Return-to-quest-point UI state.

---

## Repository / CI rules

- Keep exact reverse evidence and durable conclusions in `Genshin-Reverse`.
- Exploratory focused probes may stay on this branch.
- Full CI is mandatory before asking the user to test or before upstream submission.
- Watch CI directly; do not ask the user to report it.
- If user testing becomes necessary, provide one complete copy-paste command including
  remote fetch, branch switch, build, and run/test commands.
