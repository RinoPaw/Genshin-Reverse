# UnlockTransPointRsp runtime probe (Genshin 7.1)

This probe is the next decisive evidence step after the static 7.1 investigation reached a two-way semantic split:

```text
UnlockTransPointReq = 9369 / DMMJNICDOHM     confirmed
UnlockTransPointRsp = 36641 / NCBEHBOCBJJ    candidate
                    = 20290 / MAFFAFNMEBM    candidate
```

The goal is to observe the actual S2C CmdId produced by a known-correct Genshin 7.1 unlock transaction. A successful response can have an empty protobuf body (`retcode = 0`), so the packet header is the evidence target.

## Why runtime header evidence is now preferred

The current static investigation established all of the following:

- both surviving response types have the same one-field `int32 field 6` wire shape;
- both are consumed by 112-byte scene ACK handlers with identical normal behavior;
- the normal success path reads retcode and returns immediately;
- the apparent indirect delegate branch in each handler belongs to ILFix/hotfix method replacement, not a gameplay callback;
- the current decoded method-signature table gives each candidate exactly one external reference, its own scene handler;
- the generic unlock request submit call carries the request plus a zero second argument and does not expose a response type/callback edge;
- owner method order and nearby handler order are unstable across 7.0 -> 7.1 and mix unrelated protocol domains.

Another ranking heuristic would therefore add little information. A raw CmdId observation can close the pair directly.

## Verified decrypted packet framing

A known client packet sniffer implementation parses the game packet buffer after XOR transformation as:

```text
+0x00  uint16 BE  head magic = 0x4567
+0x02  uint16 BE  CmdId
+0x04  uint16 BE  packet-head protobuf size
+0x06  uint32 BE  message-body protobuf size
+0x0A  bytes       packet-head protobuf
+...   bytes       message-body protobuf
+end-2 uint16 BE  tail magic = 0x89AB
```

The endian interpretation is independently confirmed by the sniffer's `ReadMapped`/`WriteMapped` helpers: their default mode maps network-order bytes on little-endian Windows.

`tools/parse_decrypted_game_packet.py` validates both magic values, sizes and concatenated frames, then reports CmdId/head/body without requiring a protobuf schema.

Example:

```bash
python tools/parse_decrypted_game_packet.py \
  --file decrypted-frame.bin \
  --watch-cmd 9369 \
  --watch-cmd 36641 \
  --watch-cmd 20290
```

or:

```bash
python tools/parse_decrypted_game_packet.py \
  --hex 4567249900000000000089ab \
  --watch-cmd 9369
```

The second sample is a synthetic empty-body frame and decodes to CmdId 9369.

## Capture boundary

Do not feed raw UDP/KCP ciphertext into the parser. The useful capture point is an in-process game packet buffer after the game's packet XOR transform has been applied, or any equivalent instrumentation layer that already exposes the decrypted framed packet.

Historical client tooling used two useful boundaries:

```text
send:    KcpNative kcp_client_send_packet
receive: KcpClient TryDequeueEvent / EventRecvMsg
```

and called the game's packet XOR routine before parsing the framing above. Exact 7.1 hook identities/RVAs must be recovered against the pinned 7.1 client before implementing a maintained injector; old hook addresses must not be copied forward.

## Decisive experiment

Use an official/known-correct 7.1 session where a teleport point is genuinely unlocked. Capture a narrow interval around the unlock event with direction retained.

Expected observation:

```text
C2S  9369   UnlockTransPointReq
S2C  ?????   response to unlock flow
```

Then inspect whether the S2C stream contains:

```text
36641
```

or:

```text
20290
```

If exactly one candidate occurs in the unlock transaction, that is direct current-client/current-server evidence and can promote the mapping. Preserve the complete surrounding event window, not only the chosen CmdId, so unrelated concurrent traffic can be ruled out.

If both candidates occur in the same narrow window, do not choose by timing alone. Preserve the packet-head bytes and recover/correlate the packet-head sequence fields before promotion.

## Evidence promotion rule

A runtime result is sufficient for `confirmed` only when all of these are recorded:

1. exact client version / pinned sample identity;
2. direction (`C2S` or `S2C`);
3. decrypted frame bytes or a reproducible capture artifact;
4. observed `9369` request in the same unlock transaction;
5. candidate response CmdId extracted from the framed header;
6. enough adjacent traffic to exclude an unrelated occurrence of the candidate.

Do not use any of the following as final evidence:

- client UI appearing normal after manually sending a candidate;
- empty response protobuf body;
- ACK handler native-code equality;
- local method distance;
- ILFix/hotfix slot distance;
- old-version numeric CmdId equality.
