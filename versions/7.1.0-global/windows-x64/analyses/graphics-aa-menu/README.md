# Graphics anti-aliasing menu: DLSS 5 option

State: **ACTIVE**. No game menu patch has been validated.

## Objective

Add a distinct `DLSS 5` option to the game's anti-aliasing drop-down **without removing FSR2**. Selecting it should enable the bridge backend. The original FSR2 must remain independent. Renaming the FSR2 label is not the requested feature.

## Verified boundaries

- The maintained sample is Global 7.1.0 Windows x64, identified by `../../hashes.json`.
- `AizawaHikaru233/genshin_fsr_brigde` implements an IL2CPP **render-scale** menu hook using signatures and substitutes existing labels, NOT an additional anti-aliasing choice: https://github.com/AizawaHikaru233/genshin_fsr_brigde/blob/main/Dx11FsrBridge/RenderScaleMenu.cpp
- `CXP-2024/dlss5_for_genshinimpact` uses the FSR2-facing bridge for DLSS 5. Backend integration does not establish native dropdown ownership: https://github.com/CXP-2024/dlss5_for_genshinimpact

## First pinned-client evidence (2026-10-12)

The user's SHA-256 is `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`, exactly matching the maintained 7.1 sample. That validates use of the pinned `types.csv`, `methods.csv` and `fields.csv` with this executable.

The first read-only probe found `AntiAliasing` in the EXE `.rdata` at RVA `0x3AB387A`, plus 152 broad matching types, 729 methods, and 618 fields. These broad counts are **not a menu mapping**; most hits are Unity graphics/rendering implementation names. The next probe should use exact-owner metadata indices, including `ConsumerMode` (9384, field `SMAA_FSR2`), `FFX_FSR2` (9325), `SubpixelMorphologicalAntialiasing` (9390), and `TemporalAntialiasing` (9399), and a single precise native literal.

Quick targeted run (no large native xref scan):

```powershell
python tools/probe_graphics_aa_menu.py `
  'D:\Games\Platforms\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  --literal AntiAliasing `
  --max-rows 60 `
  --output "$env:TEMP\graphics-aa-focus.json"
```

Opt-in exact string cross-references, which may take longer:

```powershell
python tools/probe_graphics_aa_menu.py `
  'D:\Games\Platforms\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  --literal AntiAliasing `
  --with-xrefs `
  --max-rows 60 `
  --output "$env:TEMP\graphics-aa-xrefs.json"
```

Unlike the initial broad keyword scan, focused-owner records retain **obfuscated member names** belonging to the selected exact 7.1 type indices. A matching RVA/string is still only a native candidate until connected to the UI selection callback.

## Second pinned-client probe

The user ran `--literal AntiAliasing --with-xrefs` against the exact pinned EXE. The report found one ASCII hit in `.rdata`, but **zero direct native code xrefs and zero pointer holders**. The generic anti-aliasing string does not identify the game's graphics dropdown.

A fresh indexed `types.csv` search found more useful names:
- `MoleMole.MonoSettingGraphicsTab` — type 18970, 8 fields / 6 methods
- `MoleMole.MonoSettingGroup` — type 13019, 17 fields / 21 methods
- `Antialiasing` — type 9450, 7 fields (postprocessing enum, not proven UI model)
- `PerfCostGradeSetting` — type 18971 (graphics-setting-related candidate)
- `FSRQuality` — type 9330
- `ConsumerMode` — type 9384

These exact owners are now the tool's default focus list. To retrieve a *compact* owner summary, without re-running slow native xref search or large broad keyword scan:

```powershell
python tools/probe_graphics_aa_menu.py `
  'D:\Games\Platforms\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  --focus-only --max-rows 120 `
  --output "$env:TEMP\graphics-aa-ui-owners.json"
```

The report must establish the settings model, selection callback, and value persistence before attempting any game-specific UI injection. An `Antialiasing` postprocess enum is **not** automatically the menu's enum.

## UI-side direct-call map (read-only)

`tools/research_graphics_aa_callgraph.py` now uses the pinned 7.1 client metadata to automatically select actual method RVAs for the graphics settings UI types, disassemble each bounded method, and annotate direct callee owners. Unlike scanning the `AntiAliasing` string in `.rdata`, this investigates code belonging to the game graphics settings classes. It never executes injected code or changes client files.

```powershell
python -m pip install capstone
python tools/research_graphics_aa_callgraph.py `
  'D:\Games\Platforms\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  --max-body 0x1800 `
  --output "$env:TEMP\graphics-aa-ui-callgraph.json"
```

The report distinguishes methods' *candidate* ownership from a verified option model. Obfuscated methods can be found through their typeDefinitionIndex. Direct calls alone cannot resolve virtual/delegate callbacks: we must follow the UI component/asset model and confirm live option value mapping before attempting any menu patch. Preserve the full report outside the repo; it embeds code addresses and method links but no executable bytes.

## Unknowns / promotion gates

1. Identify the true owner of the anti-aliasing option model in an exact sample.
2. Establish dropdown population, selection callback, and persistence format.
3. Test safe insertion of an additional option without invalid enum IDs, bounds errors or save-data corruption.
4. Route DLSS 5 choice to the bridge while preserving untouched native FSR2 selection and fallbacks.

## Read-only evidence acquisition

From the repository root, with PowerShell 7:

```powershell
python tools/probe_graphics_aa_menu.py `
  'D:\Games\Platforms\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  --with-xrefs `
  --output 'graphics-aa-menu-probe.json'
```

The tool will refuse mismatched client hashes; this prevents using 7.1 metadata with an unrelated client. For a different client, append `--allow-unpinned` to collect only PE string/xref evidence with **no 7.1 metadata join**. Treat the observed SHA-256 as a new sample identity. Unity `FileVersion` (e.g., `2017.4.30.0`) is not the game version.

`--with-xrefs` is slower; omit it for a quick first pass. PE literal and IL2CPP metadata keyword scans do not search Unity asset bundles or runtime strings. No hits is not proof of absence. Hits are only candidates, NOT validated menu owners or hooks.

After finding a candidate, capture its option model, setting callback, persisted ID and bridge state with an opt-in, fail-closed runtime probe. Only then implement and test a fourth menu entry. Do not reuse render-scale offsets or signatures from another client version.
