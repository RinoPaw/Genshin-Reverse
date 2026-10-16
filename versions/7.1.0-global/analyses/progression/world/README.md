# Adventure Rank, World Level and Domain metadata

- [AR/WL source rows](7.1-adventure-world-level.json)
- [AR/WL and Domain mapping analysis](7.1-adventure-world-domain-schedule.md)
- [Weekday rules](../rules/7.1-daily-dungeon-schedule.json) belong to rules/.
- [Dungeon reward previews](../economy/7.1-dungeon-reward-previews.json) belong to economy/.

Configuration unlock values alone do not prove runtime World Level promotion.

- [7.1 chest Primogem region selectors](7.1-chest-primogem-region-selectors.md):
  all 100 Mondstadt/Liyue region labels confirmed; exact high-tier overrides
  include 3:1:104, 3:10:*, 3:7:703, 3:8:*, 3:19:* and 6:300:*.
- [Cross-validated 7.1 CHS names](7.1-world-area-names-chs.json):
  550/578 named through TextMap_MediumCHS, 28 explicitly unresolved;
  all 578 area-hash identities independently checked.
- [7.1 full scene chest/WorldArea audit](7.1-chest-region-full-scene-audit.md):
  41,110 Lua source files, 14,084 non-Boss chest-type gadgets, 13,007 parent
  matches, and explicit unresolved reward-zone and localization boundaries.
- [7.1 chest region selector feasibility](7.1-chest-region-selector-feasibility.md):
  pinned 16-city / 90-parent WorldArea crosswalk; confirmed mapping vs
  unresolved reward-zone exceptions and concrete selector precedence.
- [Machine-readable chest region city crosswalk](7.1-chest-region-city-crosswalk.json):
  all 90 scene/area1 IDs map to exactly one cityId, with current resource blob pins.
- [7.1 WorldArea boundary and native-selection audit](7.1-world-area-boundary-audit.md):
  parent X/Z polygon gating, child X/Z plus inclusive Y, and first-parent/
  first-child spatial priority confirmed in pinned native 7.1 code.
  Exact 7.1 original geometry is fully decoded: 22 positive child/parent
  X/Z interior conflicts remain (21 in scene 3 and one in scene 7).
  Old 5502 and 5602 positives are genuinely resolved by native
  polygon containment (both polygons valid; outside-parent area zero).
- [Exact-client native packet and polygon evidence](7.1-world-area-native-producer-evidence.json):
  sampled RVAs, field offsets, request producer, spatial branches,
  test-flag disassembly and explicit remaining unknowns.
- [Exact 7.1 WorldArea asset index](7.1-native-world-area-asset-index.json):
  all 13 original asset paths positively hash-resolved to the official
  block 0/24230448.
- [Original 7.1 raw asset fingerprints](7.1-native-world-area-raw-assets.json):
  each of the 13 asset payloads independently extracted and SHA-256
  verified; no field-level decode published yet.
- [Native-verified root array count codec](7.1-native-world-area-header-correlation.json):
  the 7.1 array reader independently confirms the exact 32-bit count
  transform; all 13 original scene root lengths total 90, matching the
  historical parent counts. Child records are still undecoded.
- [Native schema leads](7.1-native-world-area-schema-leads.json):
  historical community obfuscated field names are not present in the
  7.1 metadata; native binary reader candidates are listed by exact RVA.
- [Complete 13-scene original 7.1 binary decode](7.1-native-world-area-decoded-summary.json):
  90 parent records, 480 child polygons, 9,177 vertices; full
  source hash validation and exact consumption.
- [Native 7.1 geometry differences by area ID](7.1-native-world-area-geometry-delta.json):
  eight changed Scene 3 child outlines or heights, unchanged missing
  ID inventory, and a 5701/5705 child order swap.
- [Original-client polygon boundary scan](7.1-native-world-area-crossings-summary.json):
  22 positive parent/child X/Z crossing IDs; old 5502 and 5602
  witnesses no longer observed in original 7.1 source geometry.
- [Two resolved native 7.1 topology cases](7.1-native-world-area-target-topology.json):
  5502 and 5602 have valid native polygons and are fully covered by
  their declared parents in X/Z, unlike the historical 7.0 geometry.
- [All-scene WorldArea coverage](7.1-all-world-area-scene-coverage.json):
  13 actual geometry files for 13 scenes, including 5 hash-named files;
  90 level-1 IDs and 488 level-2 definitions, with 14 missing level-2
  geometries (13 in scene 3, one ID 80011 in scene 101).
- [All-scene coverage reproducer](../../../../../scripts/audit-7.1-world-area-coverage.py)
  with exact source pins and a fail-closed scene mapping by parent IDs.
- [Machine-readable boundary observations](7.1-world-area-boundary-observations.json)
  and [reproducer](../../../../../scripts/audit-7.1-world-areas.py)
  (no invented missing polygons).
