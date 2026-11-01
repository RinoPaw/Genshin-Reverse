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
