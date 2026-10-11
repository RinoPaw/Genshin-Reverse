'use strict';

// Read-only 7.1 Global Windows x64 client-state trace.
// The Python launcher verifies the exact GenshinImpact.exe SHA-256 before attach.
// This probe does not mutate client state, send packets, unlock anything, or log credentials.
const MODULE = 'GenshinImpact.exe';
const HOOKS = [
    { name: 'npc_talk_rsp_handler', rva: 0xA5E18C0 },
    { name: 'finish_curr_talk', rva: 0xFE57430, param: 'talk_id' },
    { name: 'lock_inter', rva: 0xFE508D0, param: 'reason' },
    { name: 'unlock_inter', rva: 0xFE552F0, param: 'reason' },
    { name: 'start_guide', rva: 0xFE284A0, param: 'guide_name' },
    { name: 'guide_start_predicate', rva: 0x758D8C0, param: 'guide_name', result: 'bool' },
    { name: 'guide_start_dispatch', rva: 0x758DBD0, param: 'guide_name' },
    { name: 'end_guide', rva: 0xFE28170, param: 'guide_name' },
    // Historical AQ356 OnSubStart35601 calls StopLocalAvatar before the talk;
    // the 7.1 continuation must be observed, not inferred from the old script.
    { name: 'stop_local_avatar', rva: 0xFE296E0 },
    { name: 'base_actor_enable_player_input', rva: 0x13AF5060, param: 'raw_input_args' },
    { name: 'actor_utils_enable_player_input', rva: 0x13A9BAE0, param: 'raw_input_args' },
    { name: 'actor_utils_enable_input_by_quest', rva: 0x13A9B510, param: 'raw_input_args' },
    { name: 'actor_utils_set_ui_lock_state', rva: 0x13AA0120, param: 'raw_input_args' },
    { name: 'actor_utils_set_quest_dialog_enable', rva: 0x13ABEED0, param: 'raw_input_args' },
    // Exact native bitmask/disabled-byte mutators; read state only, never change it.
    { name: 'input_adapter_update_input_disable', rva: 0xAC528D0, param: 'input_adapter_update' },
    { name: 'input_adapter_update_mask', rva: 0xAC529B0, param: 'input_adapter_mask' },
    { name: 'set_newbie_mask_index', rva: 0x9E2C4B0, param: 'mask_index' },
    { name: 'set_newbie_mask_compulsory', rva: 0x1163D740, param: 'compulsory' },
    { name: 'quest_list_update_receiver', rva: 0xA5CE790 },
    { name: 'newbie_setup_view', rva: 0x89FB050 },
    { name: 'newbie_on_notify', rva: 0x89FC100, verbose: true },
    { name: 'newbie_compulsory_controller', rva: 0x89F7080, verbose: true },
];
const startMs = Date.now();
let verbose = false;
let count = 0;
const MAX_GUIDE_NAME_LENGTH = 256;

rpc.exports = {
    configure(includeVerbose) {
        verbose = !!includeVerbose;
        return { verbose, hook_count: HOOKS.length };
    },
};

function safeInt(value) {
    try { return value.toInt32(); } catch (_) { return null; }
}

// Exact-7.1 Windows x64 argument positions from pinned native disassembly.
// The semantic meaning of extra arguments remains unknown.
const VERIFIED_BOOL_ARG_POSITIONS = {
    base_actor_enable_player_input: 1, // EDX, after actor RCX
    actor_utils_enable_player_input: 0, // ECX
    actor_utils_set_ui_lock_state: 0, // ECX
    actor_utils_set_quest_dialog_enable: 0, // ECX
};
function safeBool(value) {
    const n = safeInt(value);
    return n === null ? null : (n & 0xff) !== 0;
}

function safeGuideName(pointer) {
    if (!pointer || pointer.isNull()) return null;
    try {
        // IL2CPP System.String: int32 length at +0x10, UTF-16 chars at +0x14.
        const len = pointer.add(0x10).readS32();
        if (len < 0 || len > MAX_GUIDE_NAME_LENGTH) return null;
        return pointer.add(0x14).readUtf16String(len);
    } catch (_) {
        return null;
    }
}

const adapterStateById = new Map();
const adapterRequestById = new Map();
const adapterIds = new Map();
let nextAdapterId = 0;
function adapterIdentity(pointer) {
    if (!pointer || pointer.isNull()) return null;
    const key = pointer.toString();
    if (!adapterIds.has(key)) adapterIds.set(key, ++nextAdapterId);
    return adapterIds.get(key);
}
function readAdapterState(pointer) {
    if (!pointer || pointer.isNull()) return null;
    try {
        return {
            disabled: pointer.add(0x18).readU8() !== 0,
            disable_mask: pointer.add(0x1C).readU32(),
        };
    } catch (_) { return null; }
}
function emit(event) {
    event.elapsed_ms = Date.now() - startMs;
    event.thread_id = Process.getCurrentThreadId();
    event.event_index = ++count;
    send(event);
}

const mod = Process.getModuleByName(MODULE);
for (const hook of HOOKS) {
    Interceptor.attach(mod.base.add(hook.rva), {
        onEnter(args) {
            if (hook.verbose && !verbose) return;
            if (hook.param === 'input_adapter_update' || hook.param === 'input_adapter_mask') {
                this.adapterPointer = args[0];
                this.adapterId = adapterIdentity(args[0]);
                if (hook.param === 'input_adapter_update' && this.adapterId !== null) {
                    // Request argument order is from exact native method signature;
                    // do not give its bool a semantic name until its callsites are proven.
                    const request = { flag: safeBool(args[1]), source: safeInt(args[2]) };
                    const key = JSON.stringify(request);
                    if (adapterRequestById.get(this.adapterId) !== key) {
                        adapterRequestById.set(this.adapterId, key);
                        emit({ event: 'input_adapter_disable_request',
                            adapter_id: this.adapterId,
                            requested_flag: request.flag,
                            numeric_source: request.source });
                    }
                }
                return;
            }
            const event = { event: hook.name, rva: '0x' + hook.rva.toString(16).toUpperCase() };
            if (hook.param === 'talk_id') event.talk_id = safeInt(args[1]);
            if (hook.param === 'raw_input_args') {
                // Preserve raw ABI positions: IL2CPP instance-vs-static argument
                // layout is not yet native-disassembly-verified for these helpers.
                // These are numerical flags / pointers, not semantic booleans.
                event.raw_arg0 = safeInt(args[0]);
                event.raw_arg1 = safeInt(args[1]);
                event.raw_arg2 = safeInt(args[2]);
                const argIndex = VERIFIED_BOOL_ARG_POSITIONS[hook.name];
                if (argIndex !== undefined) {
                    const value = safeBool(args[argIndex]);
                    if (hook.name === 'actor_utils_set_ui_lock_state') {
                        event.ui_locked = value;
                    } else {
                        event.enabled = value;
                    }
                    // Only the selected argument's ABI and the method identity
                    // are verified; raw secondary flags are intentionally unlabeled.
                }
            }
            if (hook.param === 'reason') event.reason = safeInt(args[1]);
            if (hook.param === 'mask_index') event.mask_index = safeInt(args[1]);
            if (hook.param === 'compulsory') event.compulsory = safeInt(args[1]) !== 0;
            if (hook.param === 'guide_name') {
                event.guide_name = safeGuideName(args[1]);
                if (hook.result === 'bool') this.guideName = event.guide_name;
            }
            if (hook.result !== 'bool') emit(event);
        },
        onLeave(retval) {
            if (hook.param === 'input_adapter_update' || hook.param === 'input_adapter_mask') {
                if (this.adapterId === null) return;
                const state = readAdapterState(this.adapterPointer);
                if (state === null) return;
                const key = state.disable_mask + ':' + state.disabled;
                if (adapterStateById.get(this.adapterId) === key) return;
                adapterStateById.set(this.adapterId, key);
                emit({ event: 'input_adapter_effective_state',
                    adapter_id: this.adapterId, disabled: state.disabled,
                    disable_mask: state.disable_mask });
                return;
            }
            if (hook.result !== 'bool') return;
            // Native StartGuide tests AL after this call. A false predicate must
            // return before the downstream guide-start dispatch can run.
            const result = safeInt(retval);
            emit({
                event: 'guide_start_predicate_result',
                rva: '0x' + hook.rva.toString(16).toUpperCase(),
                guide_name: this.guideName ?? null,
                accepted: result === null ? null : (result & 0xff) !== 0,
            });
        },
    });
}

send({
    ready: true,
    module: MODULE,
    module_base: mod.base.toString(),
    hook_count: HOOKS.length,
    warning: 'Attach before 35601 starts, not merely before its dialogue. Any pre-attach input lock is unknown.',
});
