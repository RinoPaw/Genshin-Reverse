# Global 7.1 ley-line outcrop marker packet investigation

Status: **original-client protocol identities and shared receiver proven; semantic packet names, wire element semantics, and map-icon behavior not yet proven.**

## Source

Only the exact Global 7.1 Windows x64 original client identified by
`GenshinImpact.exe` SHA-256
`08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d`
and `global-metadata.dat` SHA-256
`05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0`
was used for native identity, wire parser, and client receiver evidence.

Reproduction:
- [Pinned-executable metadata and parser disassembly](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39730444937).
- [Pinned-executable blossom receiver disassembly](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39730866735).
- [Original generic-instantiation type-array bytes](https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39731366291).
- `scripts/research-blossom-protocol-71.py`, `scripts/probe-7.1-blossom-native.py`.
- `../../registry/registry.csv`, `../../registry/registry-slot-xrefs.csv`,
  `../../metadata/fields.csv`, `../../metadata/methods.csv`.

## Original packet identities and wire parsing

| CmdId | Original type | TypeDef | Original parser list field | GetCmdId RVA | Receiver |
| ---: | --- | ---: | --- | --- | --- |
| 112 | `JBHJMLHMHAC` | 26479 | tag `0x7A`, field **15** | `0x112401A0` | no confirmed direct receiver in this investigation |
| 6743 | `ABJOMOIIDHH` | 81959 | tag `0x52`, field **10** | `0x103DAB10` | `CJEDOIPINHC.FHBJPLNKLLC`, RVA `0xC78C930` |
| 20484 | `GIIGDONJFPJ` | 20805 | tag `0x72`, field **14** | `0x740F250` | `CJEDOIPINHC.KDLFMNEEKBG`, RVA `0xC790C00` |

Each row is grounded independently by the original `GetCmdId` constant
return, exact registry type slot, matching metadata declaration, and
original parser branch on the listed tag.

The metadata instances of these three packet types all have a field
named `BMDMNFLCPLF` of IL2CPP `genericinst` kind `0x15` with the
**identical runtime type index 505695**. A scan across the original
440,172 field declarations found **exactly these three occurrences**.
The original runtime type-array entry at RVA `0x35D6010` is
`37f30100000000002100150000000000`; its raw data value is
`0x1F337` (127799). This is **not** a proven generic-class registration
index or an identified protobuf element type.

## Exact client receiver relationships

The native class `CJEDOIPINHC` (TypeDef 33719) accepts
`ABJOMOIIDHH` (6743) and `GIIGDONJFPJ` (20484) as parameters.
Both handlers pass the repeated-list object to the **same** native
method `CJEDOIPINHC.FOEKNCLMGDP` at RVA `0xC78CA80`:

- 6743 handler calls the shared method through a tail jump at
  `0xC78C9E7`;
- 20484 handler calls it at `0xC790CB0` and `0xC790D37`;
- the shared method iterates the list, reads integer members from
  element offsets `+0x20` and `+0x24`, looks up client-side records,
  and calls additional owner/scene methods.

The same client class also has typed methods accepting the original
types for CmdIds 23101 (`OHIKHLJJGKH`), 6993 (`LCJIKGHHFNO`),
and 24698 (`MPCLIAJOEJB`), strengthening this class as a
blossom-related receiver *candidate*. Their semantic names in
third-party opcode lists remain unconfirmed.

## External-server discrepancy (not original-client evidence)

The AstaPS `protocol/7.1/protocol.desc` file, inspected separately,
defines a class named `BlossomBriefInfoNotify` with
`brief_info_list` at **field 13**. It currently sends this packet
using an unresolved opcode (`0`). Original client list receiver types
6743 and 20484 read fields 10 and 14 respectively; the third
structurally related type 112 reads field 15. Simply changing the opcode
of the existing field-13 AstaPS message cannot reproduce these native
receiver payloads.

The **name** `BlossomBriefInfoNotify`, its field-13 descriptor, and all
other semantic spellings from AstaPS are imported comparison controls,
**not original-client protocol naming evidence**.

## Open questions and boundaries

1. The original generic instance's *element class* is not established.
   The raw value `0x1F337` is not file-backed as a pointer in the
   sampled EXE; protected generic registration needs independent proof.
2. Neither native class 6743 nor 20484 has been proven to correspond to
   the imported names `BlossomBriefInfoNotify` or
   `WorldOwnerBlossomBriefInfoNotify`.
3. Client code that ultimately draws a world-map icon has not yet been
   traced end-to-end. The shared list receiver proves an update route
   into this client subsystem, but **does not establish on-screen output**.
4. The inner repeated element's native protobuf field numbers, server
   publish timing, and whether either packet alone is sufficient remain
   unresolved. Do not patch AstaPS with fabricated semantics or merely
   send both unconfirmed candidates.

**Promotion rule:** retain both CmdIds as native-verified identities
with unresolved semantic labels. Promote only after the receiver's
purpose and element layout are independently demonstrated in the
original client or a supported original-client runtime observation.
