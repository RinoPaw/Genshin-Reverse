'use strict';

// Genshin Impact global 7.1.0
// GenshinImpact.exe SHA-256:
// 08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d
//
// These hook points were recovered from the current client by locating the
// 0x4567/0x89AB framed packet parser/encoder and then tracing their XOR loops.
// They are RVAs, so ASLR is handled by adding them to the module base.

const MODULE_NAME = 'GenshinImpact.exe';
const S2C_POST_XOR_RVA = 0xA01846A;
const C2S_PRE_XOR_RVA = 0xA01A0EF;
const BYTE_ARRAY_DATA_OFFSET = 0x20;
const MAX_FRAME_SIZE = 16 * 1024 * 1024;
const WATCHED = new Set([9369, 36641, 20290, 25567]);

function be16(p) {
    return (p.readU8() << 8) | p.add(1).readU8();
}

function be32(p) {
    return (
        (p.readU8() * 0x1000000) +
        (p.add(1).readU8() << 16) +
        (p.add(2).readU8() << 8) +
        p.add(3).readU8()
    ) >>> 0;
}

function bytesToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let out = '';
    for (let i = 0; i < bytes.length; ++i) {
        out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
}

function emitFrames(direction, arrayObject, availableLength, hookRva) {
    try {
        if (arrayObject.isNull() || availableLength < 12 || availableLength > MAX_FRAME_SIZE) {
            return;
        }

        const data = arrayObject.add(BYTE_ARRAY_DATA_OFFSET);
        let offset = 0;
        let frameIndex = 0;

        // The receive-side parser may be handed more than one complete framed
        // packet in the same plaintext byte[] window. Walk every contiguous
        // 0x4567 ... 0x89AB frame so a watched packet cannot be missed merely
        // because it is not the first frame in the buffer.
        while (offset + 12 <= availableLength) {
            const frame = data.add(offset);
            if (be16(frame) !== 0x4567) {
                break;
            }

            const cmdId = be16(frame.add(2));
            const headSize = be16(frame.add(4));
            const bodySize = be32(frame.add(6));
            const frameSize = 12 + headSize + bodySize;
            const remaining = availableLength - offset;
            if (frameSize < 12 || frameSize > remaining || frameSize > MAX_FRAME_SIZE) {
                break;
            }
            if (be16(frame.add(frameSize - 2)) !== 0x89AB) {
                break;
            }

            const headBuffer = headSize > 0 ? frame.add(10).readByteArray(headSize) : new ArrayBuffer(0);
            const watched = WATCHED.has(cmdId);
            const payload = {
                direction,
                cmd_id: cmdId,
                hook_rva: '0x' + hookRva.toString(16).toUpperCase(),
                available_length: availableLength,
                buffer_offset: offset,
                frame_index: frameIndex,
                frame_size: frameSize,
                head_size: headSize,
                body_size: bodySize,
                head_hex: bytesToHex(headBuffer),
                watched,
            };

            // Preserve full bytes for the request, both response candidates, and
            // ScenePointUnlockNotify. Adjacent packets still emit header metadata,
            // which is enough to reconstruct the narrow transaction window.
            if (watched) {
                payload.frame_hex = bytesToHex(frame.readByteArray(frameSize));
            }

            send(payload);
            console.log(
                '[' + direction + '] cmd=' + cmdId +
                ' frame=' + frameSize +
                ' head=' + headSize +
                ' body=' + bodySize +
                ' offset=' + offset +
                (watched ? '  <WATCH>' : '')
            );

            offset += frameSize;
            frameIndex += 1;
        }
    } catch (e) {
        send({
            direction,
            hook_rva: '0x' + hookRva.toString(16).toUpperCase(),
            capture_error: String(e),
        });
    }
}

const module = Process.getModuleByName(MODULE_NAME);
console.log('[capture71] module base=' + module.base + ' size=0x' + module.size.toString(16));

Interceptor.attach(module.base.add(S2C_POST_XOR_RVA), {
    onEnter(args) {
        // At 0xA01846A:
        //   r14  = address of the managed byte[] reference
        //   r12d = available input length
        // The parser's XOR loop has completed (or was intentionally bypassed),
        // and the next block validates 0x4567 before parsing the header.
        const ref = this.context.r14;
        const length = this.context.r12.toUInt32();
        if (!ref.isNull()) {
            emitFrames('S2C', ref.readPointer(), length, S2C_POST_XOR_RVA);
        }
    },
});

Interceptor.attach(module.base.add(C2S_PRE_XOR_RVA), {
    onEnter(args) {
        // At 0xA01A0EF:
        //   r14 = complete managed byte[] frame returned from MemoryStream
        //   edi = frame length
        // The packet has 0x4567/.../0x89AB framing and the XOR loop starts at
        // 0xA01A110, so the bytes here are still plaintext.
        const arrayObject = this.context.r14;
        const length = this.context.rdi.toUInt32();
        emitFrames('C2S', arrayObject, length, C2S_PRE_XOR_RVA);
    },
});

send({
    ready: true,
    module: MODULE_NAME,
    module_base: module.base.toString(),
    s2c_post_xor_rva: '0x' + S2C_POST_XOR_RVA.toString(16).toUpperCase(),
    c2s_pre_xor_rva: '0x' + C2S_PRE_XOR_RVA.toString(16).toUpperCase(),
    watched_cmd_ids: Array.from(WATCHED),
});
