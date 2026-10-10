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
            const event = { event: hook.name, rva: '0x' + hook.rva.toString(16).toUpperCase() };
            if (hook.param === 'talk_id') event.talk_id = safeInt(args[1]);
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
    warning: 'Events only: absence of LockInter before attachment cannot prove a lock was never acquired.',
});
