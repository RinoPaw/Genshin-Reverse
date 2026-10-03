# UnlockTransPointRsp runtime probe (Genshin 7.1)

The static 7.1 investigation has reached a two-way semantic split:

```text
UnlockTransPointReq = 9369 / DMMJNICDOHM     confirmed
UnlockTransPointRsp = 36641 / NCBEHBOCBJJ    candidate
                    = 20290 / MAFFAFNMEBM    candidate
```

The remaining decisive experiment is transaction correlation in a known-correct 7.1 session. A successful response may have an empty protobuf body (`retcode = 0`), so the framed packet header and `PacketHead` sequence relation are the evidence target.

## Why runtime correlation is the boundary

Current static evidence establishes that both response candidates have the same one-field `int32 field 6` wire shape and are consumed by 112-byte scene ACK handlers with equivalent normal behavior. Their success paths read retcode and return immediately, and the apparent delegate branch belongs to ILFix/hotfix method replacement. The decoded signature table gives each candidate only its scene handler as an external signature reference. Owner-method order and nearby handler order also drift across 7.0 -> 7.1.

A current private-server control added another useful boundary: fresh waypoint tests with candidate `36641`, candidate `20290`, and no response ACK all produced the same tested visible outcome once `ScenePointUnlockNotify` was corrected to use `scene_id + point_list`. The waypoint lit, rewards appeared, the map state updated, and teleport worked in all three cases. UI/gameplay success therefore does not identify the ACK CmdId.

The project should promote one response only after a known-correct transaction gives a unique sequence-correlated S2C candidate.

## Verified decrypted packet framing

The current client independently confirms this frame layout:

```text
+0x00  uint16 BE  head magic = 0x4567
+0x02  uint16 BE  CmdId
+0x04  uint16 BE  packet-head protobuf size
+0x06  uint32 BE  message-body protobuf size
+0x0A  bytes       packet-head protobuf
+...   bytes       message-body protobuf
+end-2 uint16 BE  tail magic = 0x89AB
```

`tools/parse_decrypted_game_packet.py` validates both magic values, sizes, and concatenated frames, then reports CmdId/head/body without requiring a protobuf schema.

```bash
python tools/parse_decrypted_game_packet.py \
  --file decrypted-frame.bin \
  --watch-cmd 9369 \
  --watch-cmd 36641 \
  --watch-cmd 20290
```

A synthetic empty-body request frame can also be checked directly:

```bash
python tools/parse_decrypted_game_packet.py \
  --hex 4567249900000000000089ab \
  --watch-cmd 9369
```

## Exact current-7.1 plaintext capture points

Pinned executable:

```text
GenshinImpact.exe SHA-256
08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
```

The framing locator run `37005979777`, artifact `game-packet-framing-71` (`11226065517`), found the current parser/encoder pair. The follow-up call-edge run `37006317449`, artifact `game-packet-framing-edges-71` (`11225777817`), recovered the plaintext boundaries.

### S2C post-XOR

```text
PGKFPMENDPA method_index 503881
method RVA  0xA018360
hook RVA    0xA01846A
r14         address of managed byte[] reference
[r14]       managed byte[] object
r12d        available input length
byte data   managed byte[] + 0x20
state       packet XOR complete; framing not parsed yet
```

The immediately preceding loop performs the bytewise XOR; the framing parser then checks `0x4567`.

### C2S pre-XOR

```text
PGKFPMENDPA method_index 503894
method RVA  0xA019BB0
hook RVA    0xA01A0EF
r14         complete managed byte[] object
edi         frame length
byte data   managed byte[] + 0x20
state       framing complete; XOR has not started
```

These RVAs are exact-build evidence. Do not transfer them to another executable hash.

## Maintained collector and analyzer

The build-specific collector is kept under:

```text
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

It watches the relevant transaction IDs:

```text
9369   UnlockTransPointReq
36641  response candidate A
20290  response candidate B
25567  ScenePointUnlockNotify
```

The Python capture wrapper deliberately keeps Frida out of the package dependencies:

```bash
python -m pip install frida
python tools/runtime/capture_game_packets_71.py \
  --process GenshinImpact.exe \
  --output unlock-trans-point-71.ndjson
```

The correlation engine is now reusable package code in `genshinre.capture`. For this case:

```bash
python -m genshinre.capture unlock-trans-point-71.ndjson \
  --request-cmd 9369 \
  --candidate-cmd 36641 \
  --candidate-cmd 20290 \
  --sequence-field 3 \
  --json unlock-trans-point-71.analysis.json
```

`tools/runtime/analyze_unlock_trans_point_capture_71.py` remains as the 7.1 case-specific convenience/compatibility wrapper and also verifies that the capture session reported the expected hook RVAs.

The generic analyzer closes a transaction window at the next matching C2S request and classifies candidates as:

```text
promotable
ambiguous
candidate-observed-no-sequence
candidate-observed-sequence-mismatch
no-candidate
```

Only `promotable` is sufficient for semantic promotion. It requires exactly one candidate CmdId to share the selected `PacketHead` sequence field with the request.

## Decisive experiment

Use an official or otherwise known-correct 7.1 session where a teleport point is genuinely unlocked. Capture a narrow interval around the event with direction retained.

The useful relation is:

```text
C2S  9369   PacketHead field 3 = N
...
S2C  36641  PacketHead field 3 = N
```

or:

```text
C2S  9369   PacketHead field 3 = N
...
S2C  20290  PacketHead field 3 = N
```

A candidate merely appearing nearby is insufficient when its sequence differs or the sequence field is unavailable. If both candidates share the request sequence, preserve the result as ambiguous and inspect the surrounding traffic before adding any semantic mapping.

Traffic generated by a private server that is itself guessing the response CmdId cannot confirm the mapping.

## Evidence promotion rule

A runtime result is sufficient for `CONFIRMED` only when the record contains:

1. exact client version and pinned executable identity;
2. direction for each relevant packet;
3. decrypted frame bytes or a reproducible capture artifact;
4. observed C2S `9369` request in the same transaction;
5. decoded request `PacketHead` sequence field;
6. exactly one candidate S2C CmdId with the same sequence value;
7. enough adjacent traffic to rule out a second matching candidate or transaction overlap.

Keep the following as supporting or negative evidence only:

- client UI/gameplay appearing normal after manually sending a candidate;
- client UI/gameplay appearing normal with no ACK;
- empty response protobuf body;
- ACK handler native-code equality;
- local method distance;
- ILFix/hotfix slot distance;
- old-version numeric CmdId equality.
