# 7.1 decrypted packet capture recovery — 2026-10-02

This note preserves the research path that turned the unresolved `UnlockTransPointRsp` static tie into a concrete current-client runtime observation plan. It is intentionally chronological and records the failed semantic-string path as well as the native framing/XOR recovery so later work does not restart from KCP or old-version hook addresses.

Pinned target:

```text
GenshinImpact.exe    08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
global-metadata.dat 05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0
```

Current semantic tie:

```text
9369   DMMJNICDOHM   UnlockTransPointReq       confirmed
36641  NCBEHBOCBJJ   UnlockTransPointRsp       candidate
20290  MAFFAFNMEBM   UnlockTransPointRsp       candidate
25567  DBNMIKBJIPE   ScenePointUnlockNotify    confirmed
```

## 1. Semantic-name search did not survive the protected build

The first current-client runtime-oriented attempt searched the exact 7.1 executable and metadata for:

```text
UnlockTransPointRsp
UnlockTransPointReq
UnlockTransPoint
TransPointRsp
TransPointReq
ScenePointUnlockNotify
ScenePointUnlock
GetSceneAreaRsp
```

in both ASCII and UTF-16LE.

Actions run:

```text
run       37006202354
artifact  protobuf-semantic-strings-71
artifact  11225707914
```

Result:

```text
GenshinImpact.exe     0 semantic-name matches
global-metadata.dat   0 semantic-name matches
```

### 🕳️ Exact protobuf semantic strings

Direct semantic-name search therefore cannot distinguish the two response candidates in this build. This path should only be reopened if a new reflection/descriptor representation is independently identified. Searching the same plaintext names again adds no evidence.

A later descriptor-encoding probe was added separately to test whether generated protobuf descriptor Base64 survives even when plaintext names do not. Its result should be treated as a distinct experiment rather than retroactively upgrading the zero-hit plaintext scan.

## 2. Search the wire framing instead of the semantic name

The packet framing itself has stable binary constants:

```text
head magic  0x4567
CmdId       uint16 big-endian
head size   uint16 big-endian
body size   uint32 big-endian
tail magic  0x89AB
```

`tools/locate_game_packet_framing_71.py` uses `metadata/methods.csv` to bound native methods, raw-byte-prefilters methods that can contain the four host/byte-swapped magic forms, then accepts a hit only when Capstone decodes the value as a real immediate operand.

Actions run:

```text
run       37005979777
artifact  game-packet-framing-71
artifact  11226065517
```

Results:

```text
decoded metadata methods          711021
raw-pattern-hit methods              1403
validated immediate-hit methods         7
methods containing both magics          2
```

The only two methods containing both `0x4567` and `0x89AB` are in the same owner, `PGKFPMENDPA`:

```text
0xA018360  method_index 503881  parser-like
0xA019BB0  method_index 503894  encoder-like
```

This sharply separates the real packet-framing implementation from incidental numeric constants elsewhere in the client.

## 3. Recover the receive-side XOR boundary

The first method has decoded parameters:

```text
PGKFPMENDPA method_index 503881
RVA         0xA018360
parameters  kind_0x1D, int32, FBHCMOCPFEA, bool
```

Its early body shows an in-place byte transform:

```text
0xA018430  mov rbx, [r14]
...
0xA018459  movzx eax, byte ptr [key + index]
0xA01845E  xor byte ptr [rbx + rcx + 0x20], al
0xA018462  inc rcx
0xA018465  cmp rbp, rcx
0xA018468  jne 0xA018430
```

The next common block performs the framing check:

```text
0xA01846A  mov eax, 5
0xA01846F  cmp r12d, 0xc
...
0xA0184B4  movzx ecx, word ptr [rax + 0x20]
0xA0184B8  endian-convert uint16
0xA0184C5  cmp ecx, 0x4567
```

Recovered state at `0xA01846A`:

```text
r14       address of managed byte[] reference
[r14]     managed byte[] object
r12d      available input length
byte data [r14] + 0x20
```

The XOR loop has completed on the normal transformed path; a bypass path also joins here before framing validation. In either case, data reaching the `0x4567` parser from this block is plaintext framing.

Maintained S2C capture point:

```text
0xA01846A
```

## 4. Recover the send-side XOR boundary

The second method has decoded parameters:

```text
PGKFPMENDPA method_index 503894
RVA         0xA019BB0
parameters  MemoryStream
```

It writes the framing before transformation:

```text
0xA019C6C  mov cx, 0x4567
...
0xA01A014  mov cx, 0x89ab
```

After the stream is complete, the method obtains the managed `byte[]` and frame length:

```text
r14 = complete managed byte[]
edi = frame length
```

The outgoing XOR loop begins here:

```text
0xA01A110  cmp rcx, rbp
...
0xA01A12A  movzx eax, byte ptr [key + index]
0xA01A12F  xor byte ptr [r14 + rcx + 0x20], al
0xA01A134  inc rcx
0xA01A137  cmp rdi, rcx
0xA01A13A  jne 0xA01A110
```

Maintained C2S capture point before that loop:

```text
0xA01A0EF
```

Recovered state:

```text
r14       complete managed byte[] object
edi       frame length
byte data r14 + 0x20
```

## 5. Validate centrality through direct callers

`tools/trace_native_call_edges.py` scanned executable `E8 rel32` call candidates and validated them by disassembling the containing metadata method.

Actions run:

```text
run       37006317449
artifact  game-packet-framing-edges-71
artifact  11225777817
```

The parser has four validated direct callers across two owner types:

```text
MBFDGINGGME.KHLPKPJKJCG @ call 0x11482888
MBFDGINGGME.JBANPOAMJJN @ call 0x1148673E
NFHOALKGICN.LHPBHOBMIME @ call 0x13C5B839
NFHOALKGICN.DDMHCCKHFMJ @ call 0x13C5F33A
```

The encoder likewise has four validated direct callers:

```text
MBFDGINGGME.ICJFPIOPHCK @ call 0x11483D72
MBFDGINGGME.JBANPOAMJJN @ call 0x114865E8
NFHOALKGICN.ICJFPIOPHCK @ call 0x13C5C999
NFHOALKGICN.GACDEMPEING @ call 0x13C5D74C
```

The two transport/controller owner families share the same framing implementation. Hooking the central parser/encoder therefore avoids choosing one transport-specific caller prematurely.

## 6. Maintained runtime probe

The recovered points are implemented in:

```text
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

The probe validates frame magic and declared sizes before emitting an event. It records direction, CmdId, packet-head bytes and frame sizes for all traffic. Full frame bytes are retained for:

```text
9369
36641
20290
25567
```

This preserves the request, both response candidates and the unlock notify while keeping unrelated traffic compact enough to retain as a narrow transaction window.

## 7. Evidence boundary

The hook recovery itself does **not** decide the response semantic name. It establishes a reproducible current-client observation layer.

Promotion still requires a known-correct 7.1 transaction containing:

```text
C2S 9369
S2C 36641 or 20290
```

with enough neighboring traffic and packet-head bytes to rule out an unrelated candidate occurrence.

Traffic generated by AstaPS while AstaPS is itself guessing which response opcode to send is circular evidence and must not be used for promotion.

## Retained reusable assets

```text
tools/locate_game_packet_framing_71.py
tools/trace_native_call_edges.py
tools/runtime/capture_game_packets_71.js
tools/runtime/capture_game_packets_71.py
```

The native tools are reusable when later protocol recovery reaches a static semantic tie: stable wire/framing constants can lead to a plaintext observation boundary even when protobuf semantic names are stripped. The Actions wrappers used during discovery were retired after these exact-sample results and commands were preserved here.
