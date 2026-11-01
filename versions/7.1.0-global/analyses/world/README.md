# Global 7.1 original-client model geometry gate

**State (2026-11-01): original Unity geometry verified; world collision query not yet established.**
This work uses the installed original Global 7.1 Windows x64 client. It does not
import third-party scene/model dumps or private-server terrain estimates.

## Source authentication

- `GenshinImpact.exe`: SHA-256 `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d` (matches `nativeprofile.PROFILE_71`).
- Original design-index export `00/31049741.blk / 0000006f.dat`: SHA-256 `fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712`.
- Original resource-index export `00/31049740.blk / 0000006f.dat`: SHA-256 `24270a3c5b5388407d85ef0b20d91ea6808ba30c564071d378d4f23cb30ab3e6`. The maintained index parser validates 896,771 asset-name records and 1,447 referenced blocks. The indexes are distinct.
- Pinned read-only exporter: `EIHRTeam/AnimeStudio v1.0.0-CI`, Windows archive SHA-256 `c94eddbe3fe46c5c400d050591a46eb297d71ededc8c2376d685c988774ed110`.
- The game asset files use `Blb3` containers. No game model bytes are committed.

## Actual original meshes

| Original source block | SHA-256 | Recovered evidence |
|---|---|---|
| `00/00000890.blk` | `95254088da900edd3b13aac6a6be1f0077e4160d6280075de3eeeb25a3c50ddb` | 101 Unity Mesh records, 17 named `*_Col` meshes; complete per-mesh hashes and local bounds in the JSON snapshot |
| `00/07207014.blk` | `01120b2bb6cf1b81de7bbd27f68309279f2ddd01064aa8cf56807def71a8c68c` | `BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod1`: 230 vertices, 363 triangles; local bounds X [-20, 18], Y [-17.186668, -2.9983063], Z [-48, 52]; local vertical ray at (0,0) hits Y=-12.561386 |
| `00/00809146.blk` | `e3a30035239e4bb4d43045e4905d86f0e8d61e61a81709bb8e9c1cbd17b2abe6` | `Level_NodKrai_LongPVP_4_0_0_Magma_1752853806_Sub0_IgnoreWaterTile_Col`: 53 vertices, 51 triangles; almost perfectly flat local Y=0 |

The original `Level_Ndkl_Prop_Pedestal_A_01_Col.obj` has 289 vertices and
538 triangles. The repository's `WorldMesh` reader intersects a downward ray
at local X=Z=0 with a top-facing triangle at local Y=1.495603. The result
is a geometric local-space measurement, **not** a Mondstadt ground height.

The matching original prefab `Level_Ndkl_Prop_Deer_A_04_Col` exports a
root local Transform of position (0,0,0), rotation (0,0,0,1), scale (1,1,1),
and two serialized component references. A matching named `GameObject` was
not exported from the sampled `BigWorld_-1_14_TerrainMesh...` block;
the block-wide original GameObject AssetMap returned zero records.
Neither observation establishes actual world-instance placement or an enabled
`MeshCollider` on the rendered terrain object.

## Reproduction

Use the *exact client* files above and the pinned CLI. For the source block
`00/00000890.blk`, run the exporter twice:

```text
AnimeStudio.CLI.exe <original-block> <map-output> --game GI --types Mesh:Both --map_op AssetMap --map_type JSON --map_name meshes-00000890
AnimeStudio.CLI.exe <original-block> <mesh-output> --game GI --types Mesh:Both --names "_Col$" --export_type Convert
```

Run `scripts/probe-7.1-original-mesh.py` with the original executable, the
raw resource index export, this block, the mesh asset-map JSON and its
`Mesh/` OBJ directory; use `--output` to write the derived report, then
`--check` to compare it against this pinned snapshot.

```text
python -m unittest tests.test_worldmesh -v
```

## Remaining original-evidence gates

1. Identify which native BigWorld streams contain **scene-instance world
   transforms** for each terrain/collider mesh, including chunk origin,
   rotation, scale and parent hierarchy. A prefab root at (0,0,0) is insufficient.
2. Verify the actual physics component binding (mesh, layer, enabled state)
   from the original serialized GameObject/component graph or native runtime.
   `_Col` is a naming clue only: it also appears on water-tile meshes.
3. Bind spatially indexed, world-transformed, walkable triangles to Scene 3
   (Mondstadt) and validate independent known-position controls at different
   elevations and in caves before using any result for `fishhookTeleport`.
4. Keep the temporary server elevation estimate separate until the verified
   collision-query pipeline returns a trustworthy world-space surface.

No original source meshes, binaries, full vertex buffers, or user-local file
paths are published in the repository.

## Original 7.1 sector placement and collider metadata

A second exact-client probe traced world-instance transform ownership through the
original IL2CPP executable and its pinned metadata. Results live in
[`7.1-native-sector-transform-and-collider-schema.json`](7.1-native-sector-transform-and-collider-schema.json).
The script `scripts/probe-7.1-world-sector-native.py` verifies the original
`GenshinImpact.exe` hash, the original native type-array anchor and the
metadata CSV fields before producing its result.

- `MoleMole.Config.SECTR_StreamObjectSerialize` (type-definition index
  **58901**) declares `_gameObjectPathHash: uint64`,
  `_position`, `_rotation`, `_scale`, each with native type
  `NFFDDFHHDHG` (type-definition index **57495**).
- `NFFDDFHHDHG` declares `_x`, `_y`, `_z` as float32. The exact
  executable's Il2CppType array entry **476832** independently resolves to
  this value-type definition. These are native vector components; rotation
  units and any scene/parent transform are not yet established.
- `SECTR_LODFinInfo` (71958) declares `colliderPathHash` and
  `simpleColliderPathHash`, both uint64. This provides original-client
  names for a collider-asset binding to investigate.
- `SECTR_SceneSplitterConfig` (16791) declares `colliderLayerConfig`,
  `colliderLayerSceneWhiteList`, and `colliderInOffsetSectorBlackList`.
  `SECTR_GlobalConfig` (55978) declares `keyColliderLayers`;
  `SECTR_StreamingProfile` (79550) declares `colliderLoadRadius`.
- `MoleMole.Config.SectorBinData` (60723) declares a `datas` generic-instance
  field. Its generic argument and stored payload remain undecoded.
  `SECTR_AllBigWorld` (78003) carries `sectorPath`, `sectorSize`
  and `loadedSectors`.

These source fields establish an original sector system that represents
object transforms and collider asset identifiers. **There is no verified
instance placement or collider-enabled state yet.** Neither local mesh
raycasts nor names containing `_Col` should be used as world heights.

Reproduce against the exact Global 7.1 executable and checked-in metadata:

```text
python scripts/probe-7.1-world-sector-native.py --exe <original-7.1-exe> --metadata-dir versions/7.1.0-global/windows-x64/metadata --output versions/7.1.0-global/analyses/world/7.1-native-sector-transform-and-collider-schema.json --check
python -m unittest tests.test_world_sector_71 -v
```

**Next gate:** locate the corresponding original serialized sector data and
decode real object records with `_gameObjectPathHash`, placement coordinates,
and collider-asset identities. Only then transform the already verified mesh
triangles into scene coordinates and validate world-space raycast controls.

## Verified serialized SECTR_StreamerRoot assets

The native sector ownership above has now been linked to **actual original
`Blb3` serialized bytes**. Seven independently SHA-256-checked Global 7.1
source blocks export `SECTR_StreamerRoot` MonoBehaviour objects with the
pinned AnimeStudio CLI. Our strict binary reader consumes each exported
component in full (including Unity pointer fields, string lengths, padding,
boolean loading mode, sector lists and blacklists):

| Original block | Original `worldName` | `configName` | Sector names |
| --- | --- | --- | ---: |
| `00/00809146.blk` | `BW_BirdPinball` | `DungeonConfigNew` | 1 |
| `00/02888851.blk` | `BW_ActivityPacMan_01` | `DungeonConfig` | 5 |
| `00/03531956.blk` | `BW_Custom_Edit01` | `DungeonConfig` | 7 |
| `00/07711412.blk` | `BW_Act_Lantern02` | `DungeonConfigNew` | 1 |
| `00/07752668.blk` | `BW_Private_Witch` | `UgcHallConfig` | 5 |
| `00/12278082.blk` | `BW_Private_Drxg` | `UgcHallConfig` | 1 |
| `00/15523354.blk` | `BW_Combat_Fd_Studio` | `DungeonConfig` | 2 |

For instance, the exact original `BW_ActivityPacMan_01` root lists the
`BW_ActivityPacMan_01_-1_-1`, `BW_ActivityPacMan_01_0_0` and
`BW_ActivityPacMan_01_0_-1` sectors, as well as two `Area_LevelPacMan`
city-sector names. The UGC editing root enables `manualLoadSector`;
the other six checked examples do not.

See [the original-byte evidence](7.1-native-serialized-sector-roots.json)
for each source-block hash, raw-object hash, source pointer and complete
decoded names. The raw MonoBehaviour binaries remain local to the client;
none are committed. Use `genshinre.sectorroot71.parse_sector_root` or run:

```text
AnimeStudio.CLI.exe <original-block> <raw-output> --game GI --types MonoBehaviour:Both --names "^SECTR_StreamerRoot$" --export_type Raw
python scripts/probe-7.1-original-sector-roots.py --exe <original-7.1-exe> --blocks <original-block-group-00> --raw-exports <seven-export-folders> --output versions/7.1.0-global/analyses/world/7.1-native-serialized-sector-roots.json --check
python -m unittest tests.test_sector_root_71 -v
```

This confirms native scene roots reference independently named sector chunks.
The seven checked objects belong to activity/UGC scenes. **No checked root is
evidence of the Scene 3 / Mondstadt terrain placement.** World-space
transforms and enabled MeshCollider data remain the next gate before AstaPS
can replace the fishhook height estimate with a real collision raycast.
