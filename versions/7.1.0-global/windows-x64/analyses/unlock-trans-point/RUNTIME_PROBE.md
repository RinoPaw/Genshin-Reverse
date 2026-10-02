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

The current client itself now independently confirms the packet framing:

```text
+0x00  uint16 BE  head magic = 0x4567
+0x02  uint16 BE  CmdId
+0x04  uint16 BE  packet-head protobuf size
+0x06  uint32 BE  message-body protobuf size
+0x0A  bytes       packet-head protobuf
+...   bytes       message-body protobuf
+end-2 uint16 BE  tail magic = 0x89AB
```

The endian conversion methods used by the recovered parser/encoder are current-client methods on `uint16` / `uint32`. This also agrees with historical sniffer implementations.

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

## Exact current-7.1 plaintext capture points

Pinned executable:

```text
GenshinImpact.exe SHA-256
08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
```

The framing locator run `37005979777`, artifact `game-packet-framing-71` (`11226065517`), found only seven decoded methods containing framing-magic immediates. Only two methods contain both `0x4567` and `0x89AB`; both belong to `PGKFPMENDPA` and form the packet parser/encoder pair.

The follow-up call-edge run `37006317449`, artifact `game-packet-framing-edges-71` (`11225777817`), recovered their callers, full native bodies and XOR boundaries.

### S2C parser

```text
PGKFPMENDPA method_index 503881
start RVA   0xA018360
signature   (kind_0x1D, int32, FBHCMOCPFEA, bool)
```

The function first transforms the incoming managed `byte[]` in place:

```text
0xA018430  mov rbx, [r14]
...
0xA018459  movzx eax, byte ptr [key + index]
0xA01845E  xor byte ptr [rbx + rcx + 0x20], al
0xA018462  inc rcx
0xA018465  cmp rbp, rcx
0xA018468  jne 0xA018430
```

Immediately after that loop:

```text
0xA01846A  mov eax, 5
0xA01846F  cmp r12d, 0xc
...
0xA0184B4  movzx ecx, word ptr [rax + 0x20]
0xA0184B8  endian-convert uint16
0xA0184C5  cmp ecx, 0x4567
```

Therefore the maintained S2C plaintext hook is:

```text
RVA       0xA01846A
r14       address of managed byte[] reference
[r14]     managed byte[] object
r12d      available input length
byte data managed byte[] + 0x20
state     packet XOR complete (or intentionally bypassed); framing not parsed yet
```

This point is superior to a KCP-level hook for the current task because the buffer is already plaintext and still contains the complete framed packet.

### C2S encoder

```text
PGKFPMENDPA method_index 503894
start RVA   0xA019BB0
signature   (MemoryStream)
```

The encoder writes the full plaintext frame first:

```text
0xA019C6C  mov cx, 0x4567
...
0xA01A014  mov cx, 0x89ab
```

It then obtains the completed managed `byte[]` from the stream. At the end of frame construction:

```text
r14 = complete managed byte[]
edi = frame length
```

The XOR loop begins at:

```text
0xA01A110  cmp rcx, rbp
...
0xA01A12A  movzx eax, byte ptr [key + index]
0xA01A12F  xor byte ptr [r14 + rcx + 0x20], al
0xA01A134  inc rcx
0xA01A137  cmp rdi, rcx
0xA01A13A  jne 0xA01A110
```

Therefore the maintained C2S plaintext hook is:

```text
RVA       0xA01A0EF
r14       complete managed byte[] object
edi       frame length
byte data managed byte[] + 0x20
state     framing complete; XOR has not started
```

These two RVAs are build-specific. Do not transfer them to another executable hash.

## Maintained runtime collector

The repository now carries:

```text
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

The JavaScript attaches at the two current RVAs above. It validates `0x4567`, declared head/body sizes and `0x89AB` before emitting a packet event. Every packet contributes direction/CmdId/head metadata; full frame bytes are preserved for the watched transaction IDs:

```text
9369   UnlockTransPointReq
36641  response candidate A
20290  response candidate B
25567  ScenePointUnlockNotify
```

The Python wrapper only needs the runtime Frida binding; it is deliberately not a project dependency:

```bash
python -m pip install frida
python tools/runtime/capture_game_packets_71.py \
  --process GenshinImpact.exe \
  --output unlock-trans-point-71.ndjson
```

Use the probe only in a research environment where process instrumentation is permitted. The maintained evidence target remains a known-correct 7.1 transaction; traffic generated by a private server that is itself guessing the response CmdId cannot confirm the semantic mapping.

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

If both candidates occur in the same narrow window, do not choose by timing alone. The collector preserves packet-head bytes; correlate the packet-head sequence fields before promotion.

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
