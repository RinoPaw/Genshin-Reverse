# ScenePointUnlockNotify field mapping (global 7.1)

This note records the exact wire/semantic field mapping recovered for the pinned official global Genshin 7.1 client. It was investigated after a private-server runtime probe persisted an unlocked waypoint immediately but left the live map icon gray until a later scene-entry resync.

Pinned 7.1 sample:

```text
GenshinImpact.exe    08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

## Exact current parser layout

Current type: `DBNMIKBJIPE` / `ScenePointUnlockNotify` / CmdId `25567`.

The official 7.1 protobuf parser `NLGBJEEJDLG @ 0x1252BE50` accepts the following tags and object fields:

```text
wire field 2   scalar uint32     object +0x38
wire field 4   repeated uint32   object +0x28
wire field 6   repeated uint32   object +0x30
wire field 8   repeated uint32   object +0x20
wire field 15  repeated uint32   object +0x18
```

Relevant parser tag pairs are `0x20/0x22` for field 4, `0x30/0x32` for field 6, `0x40/0x42` for field 8, and `0x78/0x7A` for field 15. Field 2 is the scalar `scene_id` path.

Evidence workflow: `dump-scene-point-unlock-proto-methods.yml`, run `37017695170`, job `110872536619`, artifact `11231765970`.

This directly disproves same-version public proto definitions that place the two extra repeated lists at fields `50000` and `50001` for this exact pinned global client.

## Semantic mapping from exact handler alignment

The 7.0 and 7.1 `ScenePointUnlockNotify` handlers are instruction-for-instruction structurally identical after token normalization:

```text
7.0 handler  GDKGKIHBOPF @ 0xB6F2870
7.1 handler  IPADDHFIGMF @ 0xF05F0F0
token similarity        1.0
instruction count       1093 / 1093
```

The known 7.0 semantic object layout is:

```text
+0x20  unhide_point_list
+0x28  locked_point_list
+0x30  point_list
+0x18  hide_point_list
+0x38  scene_id
```

Aligned handler accesses transfer those semantics to the current 7.1 object offsets:

```text
old +0x30 point_list         -> current +0x18 -> wire field 15
old +0x28 locked_point_list  -> current +0x28 -> wire field 4
old +0x18 hide_point_list    -> current +0x30 -> wire field 6
old +0x20 unhide_point_list  -> current +0x20 -> wire field 8
old +0x38 scene_id           -> current +0x38 -> wire field 2
```

Therefore the current official global 7.1 semantic mapping is:

```text
scene_id           = 2
locked_point_list  = 4
hide_point_list    = 6
unhide_point_list  = 8
point_list         = 15
```

Evidence workflow: `probe-7.0-7.1-scene-point-unlock-handler-fields.yml`, run `37016931577`, job `110869981607`, artifact `11230770050`.

## AstaPS implication

The current AstaPS generated 7.1 class exposes:

```text
POINT_LIST_FIELD_NUMBER = 15
UNHIDE_POINT_LIST_FIELD_NUMBER = 4
HIDE_POINT_LIST_FIELD_NUMBER = 6
HBKHEKLMEKN_FIELD_NUMBER = 8
SCENE_ID_FIELD_NUMBER = 2
```

The generated semantic alias for field 4 is wrong. Official 7.1 client behavior identifies field 4 as `locked_point_list`; field 8 is the actual `unhide_point_list`.

AstaPS's live unlock packet had been sending both:

```text
point_list field 15 = pointId
field 4             = pointId   // generated API calls this unhide, client treats it as locked
```

That produces a contradictory live notification: the same point is presented in the unlock list and lock list. This is a strong explanation for the observed runtime behavior where persisted unlock state is correct immediately but the map remains gray until a later scene resync reconstructs state.

A controlled AstaPS test branch now removes field 4 from the unlock notification and sends only `scene_id + point_list`. Runtime confirmation is still required before promoting any `UnlockTransPointRsp` candidate.

## Failed approach retained

An earlier parser-to-parser `SequenceMatcher` field transfer produced an impossible mapping in which historical `unhide_point_list` aligned to current field 2, colliding with the independently established `scene_id = 2`. Do not reuse raw parser instruction-position alignment as semantic evidence. The parser is authoritative for current wire numbers/object offsets; semantic transfer here comes from the exact 1.0 lifecycle-handler alignment plus the known 7.0 field semantics.
