# 7.1 special-energy resource rename — historical AstaPS import

State: `COMPLETE` as a provenance migration. The imported technical claims keep the validation level of their AstaPS source and were not independently revalidated during this move.

## Source

The durable source is `MeChen618/AstaPS` PR #42, **Fix Mavuika and Skirk special energy on 7.1 resources**.

- source branch: `fix/special-energy`
- source commits:
  - `b40002811f6dccbea32fd0551677ea432cd83a9b` — `Map 7.1 special energy and Nightsoul action names`
  - `521f90cb4364e1dd1ee2b53a6b01a1b8a40fa220` — `Read 7.1 special energy fields from the skill excel`
- merge commit: `0c00f4d07c1ebbbf2b1aec4876f5851e846d86d4`
- source validation: six focused unit tests passed as part of the AstaPS test suite; the PR explicitly said the change had not been tested in game

## Imported resource-name mappings

The source recorded that 7.1 resources used new names for existing server-side ability concepts:

| 7.1 resource name | Existing AstaPS handler/type |
| --- | --- |
| `ReviveSpecialEnergy` | `AddSpecialEnergy` |
| `AddNyxValue` | `NyxAdd` |
| `SetNyxValue` | `NyxSet` |
| `ChangeNyxValueMixin` | `NyxCostMixin` |

The source counted those new names in the resource set and added them as deserialization aliases rather than introducing separate server semantics. `ChangeNyxValueMixin` also used a `value` field for its delta in that implementation.

These statements are preserved as historical resource evidence. This migration does not independently verify the resource corpus or promote the names into any canonical Genshin-Reverse dataset.

## Imported skill-excel field spellings

The source recorded two 7.1 skill-excel spellings:

- `specialEnergyCostMax`
- `specialEnergyCostStart`

In AstaPS's existing model they were mapped onto the older fields named `specialEnergyMin` and `specialEnergyMax`. The source documented the model's semantics as:

- `specialEnergyMin`: bar size
- `specialEnergyMax`: burst cost

The focused source tests used these rows:

| Character | Skill id | Imported bar size | Imported burst cost |
| --- | ---: | ---: | ---: |
| Mavuika | `11065` | `200` | `100` |
| Skirk | `11145` | `100` | `50` |

The names `specialEnergyMin` / `specialEnergyMax` are AstaPS model names and can be misleading; this note preserves what the source implementation meant by them rather than treating the names themselves as client semantics.

## Regression tests preserved by the source

`NyxActionNamesTest` covered the 7.1 action/mixin aliases and zero-value behavior. `SpecialEnergySkillTest` covered deserialization of the two skill-excel rows above. Their main maintenance value is that the source branch converted recovered resource spellings into executable regression constraints instead of leaving them only in a commit message.

## What this import establishes

This directory establishes provenance and prevents the AstaPS branch history from being the only durable record of the work. It does not add a new reverse-engineering conclusion and it does not strengthen the original evidence level.

If this topic is revisited, use the exact 7.1 resource source or another current-version artifact as the evidence reference and add machine-queryable `evidence.json` only when there is a need to promote or compare claims under `docs/analysis-contract.md`.
