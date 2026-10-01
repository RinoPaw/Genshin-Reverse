# Registry recovery pipeline

The 7.1 protocol registry should be recovered in stages so an attractive false positive cannot silently become a canonical CmdId mapping.

## Stage 0 — exact sample and metadata

Fingerprint the samples, extract metadata indexes, and require the 7.1 anchor set to pass first. See `metadata-extraction.md`.

## Stage 1 — constant-return `GetCmdId` candidates

With a complete `metadata/methods.csv` containing method RVAs:

```bash
genshinre scan-constant-cmdids \
  inputs/GenshinImpact.exe \
  versions/7.1.0-global/windows-x64/metadata/methods.csv \
  work/getcmdid-candidates.csv
```

The scanner maps every metadata method RVA back into the PE and recognizes a deliberately narrow x86/x64 body:

```text
mov eax, IMM32
ret
```

Optional ENDBR64 and small NOP padding are accepted. The output is **candidate data**. Many ordinary client methods can return small constants, so this stage alone cannot establish a protocol registry.

For the preserved 7.1 sample, an important sanity anchor is:

```text
HJDNCHODGOL @ RVA 0x10587260 -> 26105
```

The generated summary reports whether that exact anchor was recovered. If it fails, investigate metadata/RVA/sample mismatch before doing protocol work.

## Stage 2 — registration-table identity

The earlier successful 7.1 audit recovered an RX CmdId-to-type registration table with 4,896 unique CmdIds. That stronger structure is still the target because it binds numeric IDs to protobuf types and supplies registration context/direction information.

Do not turn all Stage-1 constant-return rows into `registry.csv`. Use them to locate/validate the registration machinery, then emit the table through `normalize-registry`.

## Stage 3 — independent control set

Build the current AstaPS control set and cross-check it:

```bash
genshinre import-opcodes-java \
  ../AstaPS/src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java \
  work/known-opcodes.csv

genshinre crosscheck-registry \
  versions/7.1.0-global/windows-x64/registry/registry.csv \
  work/known-opcodes.csv \
  --output work/registry-crosscheck.json
```

The preserved earlier recovery contained 4,896 unique CmdIds and covered all 1,540 then-known AstaPS numeric opcodes. Those counts are regression evidence, not values to force. A regenerated dataset must explain genuine differences.

## Stage 4 — semantic naming

The registration table gives numeric identity plus obfuscated type. Semantic names require parser shape, handler/sender xrefs, runtime observations, or another independent current-version source. Historical numeric equality stays `historical-only`.
