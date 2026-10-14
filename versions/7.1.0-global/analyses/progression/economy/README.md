# Native reward economy

## Ordinary chest reward source review (2026-10-15)

[Four-grade chest source and statistics audit](7.1-chest-reward-evidence.md): all 96 legacy tagged root IDs exist, reaching 612 nodes and 198 terminal IDs, but their Server data predates 7.1; 1,295 of 6,141 authored ordinary-grade chest instances have no region tag, and only 295/300 untagged explicit drop IDs point to present nonempty tables. Wiki gives reward ranges and possible item families, not complete per-item probabilities. Operator-authored pools therefore require clear provenance and a single reused drop executor; never promote legacy values to 7.1-native rates.

## DropTable provenance (2026-10-13)

[Source comparison and reproducibility report](7.1-drop-table-provenance.md): AstaPS-Resource's two `Server/` drop tables are identical to LunaGC-Resources data already present in April 2026 (`6.5.0 GC`), which recovers **0** missing roots. A separate, later **LunaGCR 7.0** comparison finds **68 of 140** missing 7.1 Dungeon roots (24 talent, 24 weapon, 20 artifact) with 94 of the 100 old-only subnodes actually reachable from those restored roots; all 68 recovered graphs have 7.1 preview-matching item families, but their weights have an explicit **6.6-era** history and are **not** verified 7.1-native rates. The other **72** roots remain unresolved. The original extraction provenance remains unverified.

## Historical 3/4-substat branch audit (2026-10-15)

The [reproducible initial-substat variant audit](../../windows-x64/analyses/artifact-generation/7.1-reliquary-drop-variant-weights.json) finds **27** `randomType = 0` source branches pairing **8000** weight on 3-substat 5-star item IDs with **2000** on otherwise corresponding 4-substat IDs. Each has 10 fully resolved leaf item IDs per side; all 27 branches are reachable from distinct Dungeon roots. The other 27 present-root artifact Dungeons have no five-star leaves, while **44 of 98** artifact Dungeon roots are absent from this historical dataset. This is evidence of configured weights in **6.5-era Server data**, not confirmed official 7.1 runtime probabilities. The [DropTable provenance report](7.1-drop-table-provenance.md) governs its promotion boundary.

## Current AstaPS Dungeon claim-path audit (2026-10-13)

[Current static claim-path snapshot](7.1-current-asta-dungeon-reward-audit.json) is pinned to [AstaPS 1c2cb794](https://github.com/RinoPaw/AstaPS/commit/1c2cb79444ae911baf1fb8a11875ac32ae9783c4) (PR #120), with eight checked server blobs and the original source-graph/preview snapshots. Its **B-level static conclusions are candidates**, not verified native probabilities or successful in-game claims.

- Source coverage: **373** Dungeon rows, **166** linked roots, **140** missing roots, **67** without pointers.
- **278** configured `DungeonDrop.json` pools: **262** pass deterministic structural checks, **16** fail (**6** empty item pools and **10** artifact pools containing weapon-ascension materials). Structural validity does not establish ItemData/family verification or an official drop rate.
- Candidate routes: **131** native-with-proxy fallback, **35** native-only, **131** proxy-only; **75** lack a payable source in the audited DomainStatue claim path and Dungeon **5116** fails the initial source gate. A candidate can still fail runtime validation.
- Immediate repair leads: the **9** missing-root artifact domains with rejected proxy pools are `4480, 4484, 4665, 4683, 4687, 5018, 5022, 5060, 5064`.
- All **66** Boss Dungeon rows lack a payable source *in this particular claim path*. Other world/weekly Boss consumers have not been audited, so this does not prove all Boss rewards are broken.
- The current server binds `IAOMJCLOIEL` to `statueDrop`, checks native leaf families and proxy structure, and never treats reward-preview items as payable loot. Rejected pools do not by themselves trigger the old charge-then-exception outcome; inventory/payment checks and a receipt journal now guard granting, although MongoDB writes are not multi-document atomic.

Reproduce with the pinned server checkout from this repository root:

```sh
python -m genshinre.currentdungeonaudit /path/to/AstaPS --check
python -m unittest tests.test_current_dungeonaudit -v
```

The audit fails closed on changed server blobs and exact source snapshots. A later AstaPS commit requires a new model check and explicit re-pinning.

### Seven artifact roots rejected by the preview-family gate (2026-10-13)

The [native-only artifact validation audit](7.1-artifact-native-only-claim-audit.json) cross-joins the exact 7.1 `DisplayItemExcelConfigData` (`ITEM_DISPLAY`, with `param` identifying a set), `ReliquaryExcelConfigData` (`ITEM_RELIQUARY`, with `setId`), reward previews and reachable positive-weight drop leaves against the current AstaPS claim consumer. A [reproducible collector](../../../../../genshinre/reliquaryclaimaudit.py) pins the two resource blobs and prior research snapshots.

**Seven additional artifact Dungeons** `5000, 5001, 5002, 5008, 5050, 5100, 5101` have an existing native root but an invalid proxy pool. Every native root reaches genuine reliquary item IDs, and their set IDs exactly match the advertised preview sets. Yet their previews contain only display-item IDs for artifacts, not inventory-reliquary IDs. The current `DomainStatueDropService` filters the preview through `ItemData` and `ITEM_RELIQUARY`, leaving an empty set of expected artifact families. As `DomainDropSafety.matchesNativeFamilies` then rejects the otherwise present native root and the proxy was already rejected, the selected reward source is `NONE`. The claim aborts **before payment** in this pinned implementation.

This narrows the artifact-specific source failure set to **16 candidates**: the nine missing-root/invalid-proxy rows above plus these seven existing-root/invalid-proxy rows. It does **not** establish in-game reachability or successful/failed live claims. A future repair should use a verified `DisplayItem.param → Reliquary.setId` relation for artifact-family validation, **not** accept all native roots blindly; the actual 7.1 native distribution and correct claim path still need testing.

Reproduce against the exact pinned `AstaPS-Resource` checkout:

```sh
python -m genshinre.reliquaryclaimaudit /path/to/AstaPS-Resource --check
python -m unittest tests.test_reliquaryclaimaudit -v
```

### Historical configured reward audit (2026-10-09)


- [Native drop economy](7.1-native-drop-economy.md) covers Ley Line yields and unresolved Domain/Boss distributions.
- [Dungeon previews](7.1-dungeon-reward-previews.json) contain advertised items, not probabilities.
- [Growth baseline](../7.1-resource-growth-observations.json) supplies progression requirements.
- [Time and claim gates](../rules/7.1-time-gates.md) are kept separately.

Do not infer exact farming counts from reward previews.

- [7.1-talent-domain-drop-links.json](7.1-talent-domain-drop-links.json): 104 source talent Domains, 56 linked drop roots, 48 unresolved roots; 118 reachable drop nodes (raw weight/count strings, no probability inference). The 56 resolved roots reach 39 terminal material IDs, validated against DropMaterial rows and each Dungeon’s preview. Generated by `scripts/collect-7.1-talent-domain-drops.py` with six pinned source-blob checks. The 104 rows map uniquely to 8 talent DungeonEntry material families using reward-preview item membership; this is not a direct runtime foreign key.

- [AstaPS talent-domain server proxy](7.1-talent-domain-server-proxy.json): 96 matching Dungeon IDs and 48 cases where no 7.1 resource drop root exists. Pin: `AstaPS@b1c5af21` / `data/DungeonDrop.json`. This is *B implementation evidence*, never native 7.1 rates. Collector: `scripts/collect-7.1-talent-domain-server-proxy.py`.

- [Dungeon drop links](7.1-domain-drop-links.json): all 373 daily/Boss rows, 166 linked roots, 140 missing roots and 67 rows without a pointer; 630 reachable raw nodes; explicit weekday references for 96 talent and 96 weapon rows. The cross-domain graph complements the focused talent material and server-proxy snapshots. Generated by `scripts/collect-7.1-domain-drops.py` with four pinned source-blob checks.

- [Client Dungeon-config candidate](../../../windows-x64/analyses/dungeon-progression/README.md): exact 7.1 Windows native reader, 67-field owner candidate, optional four-byte wire read/XOR and wrapped store at `0xE8`. All 2,377 native rows now scan to EOF after an opaque four-byte header; selected aliases and the two target root references match the pinned resource. The header count transform, runtime loading and claim consumer remain unresolved. A design-index search rejects 66 explicit drop-table path candidates; alternative names/indexes remain open. This does not recover the 140 missing roots or native drop probabilities.

## AstaPS configured reward audit

[7.1-asta-dungeon-reward-audit.json](7.1-asta-dungeon-reward-audit.json) audits
373 daily/Boss rows against AstaPS `b1c5af21` and resource `b0f3a279`.
This is **B: server implementation evidence**, conditional on successful loading
of these exact files. It does not assert live dungeon reachability or native rates.
All 16 server source/data blobs are checked before the model runs.

Configured paths: **266 server proxies, 106 preview fallbacks, 1 initial-gate
rejection**. The last is test-state Dungeon **5116**, not a confirmed playable
broken domain. Preview fallback covers 66 Boss, 8 talent and 32 weapon rows.

Priority findings:

- **6 guaranteed empty-pool draw exceptions**: `5000, 5001, 5002, 5008, 5100,
  5101`. A positive artifact count is paired with `items: []`.
  `rollRewards` reaches `Utils.drawRandomListElement` on the empty list;
  `nextInt(0, 0)` throws. `handleCost` executes before this roll, with no rollback
  in `getStatueDrops`; actual charging remains conditional on a valid claim
  and its cost configuration. The partially built local reward list is never
  added to inventory.
- **10 reliquary proxies contain weapon-domain materials**: `4480, 4484, 4665,
  4683, 4687, 5018, 5022, 5050, 5060, 5064`, each containing `114021–114023`.
  Identity is corroborated by membership in the weapon-domain source previews;
  exact artifact piece/set comparison is not available in this input set.
- **16 preview fallbacks omit domain materials**: `4200–4203, 4300–4303,
  5210–5213, 5250–5253`. `RewardPreviewData.onLoad` filters out IDs without
  a count. These previews consequently retain XP/Mora/friendship but no
  corresponding books/weapon materials. All sixteen source roots are already
  present in the resource DropTable, so field binding is a concrete repair lead.
  These are release-state rows; scene
  access and actual claims still require gameplay verification.
- All **306 nonzero source roots** are stored under `IAOMJCLOIEL`; this Java
  `DungeonData` only declares unaliased `statueDrop`. Its Gson builder has no
  Dungeon adapter, and ordinary JSON loading does not rename that key.
  Consequently the source roots do not enter this configured claim path.

Preview conversion uses the last semicolon endpoint, ceilings decimals, and
omits entries with no count. Material-domain rewards then have a custom **×3**
boost, conditional on ItemData/material classification; common currency/XP IDs
are exempt. Preview fallback does not double amounts for condensed resin.
Reliquary bonuses remove `105005` and add `105003`/`105002` when neither exists.
These custom behaviors must be retained when comparing configured base drops
with inventory yields. Shared group summaries are keyed by SHA-256 to avoid
repeating large pools; large item pools retain a source-list fingerprint/sample.

The maintained command verifies the supported server profile and fingerprints
all resource inputs. Obtain the pinned server files listed in `source.server.files`
into a local checkout (or equivalent paths), then reproduce:

```sh
genshinre audit dungeon /path/to/AstaPS-Resource /path/to/AstaPS \
  --resource-source RinoPaw/AstaPS-Resource@b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd \
  --check versions/7.1.0-global/analyses/progression/economy/7.1-asta-dungeon-reward-audit.json
```

Next: first fix and claim-test empty pools/cost safety, then correct the ten
material-filled artifact proxies using verified artifact data; restore material
rewards for the sixteen fallback domains. Community drop statistics can guide
quantity distributions after these structural defects are addressed.
