"""Exercise the 7.1 read-only Frida hook callbacks against a simulated JS host.

This proves serialization and state correlation, NOT that Frida can attach to
the client, that the hard-coded RVAs execute, or that any guide is the cause.
"""
from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools/runtime/capture_amber_guide_locks_71.js"

# Frida APIs are mocked; no client process, binary, injection or network needed.
JS_HOST_TEST = r"""
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const hooks = new Map();
const events = [];
const host = {
    rpc: { exports: {} },
    Process: {
        getModuleByName(name) {
            assert.equal(name, 'GenshinImpact.exe');
            return { base: { add(rva) { return rva; }, toString() { return 'mock-module'; } } };
        },
        getCurrentThreadId() { return 19; },
    },
    Interceptor: {
        attach(rva, callbacks) {
            assert.equal(hooks.has(rva), false, 'duplicate hook RVA');
            hooks.set(rva, callbacks);
        },
    },
    send(event) { events.push(event); },
};

vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), host, {
    filename: 'capture_amber_guide_locks_71.js',
    timeout: 3000,
});
assert.equal(hooks.size, 22);
assert.equal(events.length, 1);
assert.equal(events[0].ready, true);
assert.equal(events[0].hook_count, 22);
const config = host.rpc.exports.configure(true);
assert.equal(config.hook_count, 22);
assert.equal(config.verbose, true);

function value(n) { return { toInt32() { return n; } }; }
function unreadable() { return { toInt32() { throw new Error('read failed'); } }; }
function stringPointer(s) {
    return {
        isNull() { return false; },
        add(offset) {
            if (offset === 0x10) return { readS32() { return s.length; } };
            if (offset === 0x14) return { readUtf16String(n) { return s.slice(0, n); } };
            throw new Error('unexpected string pointer offset');
        },
    };
}
function invoke(rva, args, returnValue) {
    const hook = hooks.get(rva);
    assert.ok(hook, 'hook missing: ' + rva);
    const state = {};
    hook.onEnter.call(state, args);
    if (returnValue !== undefined) hook.onLeave.call(state, returnValue);
}
function eventOf(name) { return events.filter(x => x.event === name); }
function last(name) { return eventOf(name).at(-1); }

// The guide predicate's argument is a managed UTF-16 string and its result
// must be observed, never altered or replaced.
invoke(0x758D8C0, [value(0), stringPointer('GuideQuestGuide')], value(0));
assert.equal(last('guide_start_predicate_result').guide_name, 'GuideQuestGuide');
assert.equal(last('guide_start_predicate_result').accepted, false);
invoke(0x758D8C0, [value(0), stringPointer('GuideQuestGuidePC')], value(1));
assert.equal(last('guide_start_predicate_result').accepted, true);
invoke(0xFE284A0, [value(0), stringPointer('GuideQuestGuidePC')]);
assert.equal(last('start_guide').guide_name, 'GuideQuestGuidePC');

// Boolean decoding must preserve unreadable arguments as unknown.  The
// earlier code incorrectly converted null !== 0 into "true".
invoke(0x1163D740, [value(0), unreadable()]);
assert.equal(last('set_newbie_mask_compulsory').compulsory, null);
invoke(0x1163D740, [value(0), value(0)]);
assert.equal(last('set_newbie_mask_compulsory').compulsory, false);
invoke(0x1163D740, [value(0), value(1)]);
assert.equal(last('set_newbie_mask_compulsory').compulsory, true);

// Exact-client disassembly verifies which argument is the primary bool.
invoke(0x13AF5060, [value(0), value(1), value(0)]);
assert.equal(last('base_actor_enable_player_input').enabled, true);
assert.equal(last('base_actor_enable_player_input').secondary_flag, false);
assert.equal('raw_arg0' in last('base_actor_enable_player_input'), false);
invoke(0x13A9BAE0, [value(0), value(1), value(1)]);
assert.equal(last('actor_utils_enable_player_input').enabled, false);
assert.equal(last('actor_utils_enable_player_input').secondary_flag, true);
assert.equal('raw_arg2' in last('actor_utils_enable_player_input'), false);
invoke(0x13AA0120, [value(1), value(0), value(0)]);
assert.equal(last('actor_utils_set_ui_lock_state').ui_locked, true);
invoke(0x13AA0120, [value(0), value(0), value(0)]);
assert.equal(last('actor_utils_set_ui_lock_state').ui_locked, false);

// Native input adapter: correlate request -> post-call disabled/mask.
// Pointer may be used internally for identity, but must not be logged.
let mask = 0, disabled = false;
const adapter = {
    isNull() { return false; },
    toString() { return 'PRIVATE_NATIVE_POINTER_7F'; },
    add(offset) {
        if (offset === 0x18) return { readU8() { return disabled ? 1 : 0; } };
        if (offset === 0x1C) return { readU32() { return mask; } };
        throw new Error('unexpected adapter memory offset');
    },
};
invoke(0xAC528D0, [adapter, value(1), value(2)], value(0));
assert.equal(last('input_adapter_effective_state').disabled, false);
assert.equal(last('input_adapter_effective_state').disable_mask, 0);
const same = hooks.get(0xAC528D0);
const context = {};
same.onEnter.call(context, [adapter, value(1), value(2)]);
mask = 0x3; disabled = true;
same.onLeave.call(context, value(0));
assert.equal(last('input_adapter_effective_state').adapter_id, 1);
assert.equal(last('input_adapter_effective_state').disable_mask, 3);
assert.equal(last('input_adapter_effective_state').disabled, true);
const before = events.length;
invoke(0xAC528D0, [adapter, value(1), value(2)], value(0));
invoke(0xAC529B0, [adapter], value(0));
assert.equal(events.length, before, 'unchanged requests/states must be deduplicated');
const maskCtx = {};
hooks.get(0xAC529B0).onEnter.call(maskCtx, [adapter]);
mask = 0; disabled = false;
hooks.get(0xAC529B0).onLeave.call(maskCtx, value(0));
assert.equal(last('input_adapter_effective_state').disabled, false);
assert.equal(last('input_adapter_effective_state').disable_mask, 0);

const output = JSON.stringify(events);
assert.equal(output.includes('PRIVATE_NATIVE_POINTER_7F'), false);
assert.equal(events.every((e, i) => i === 0 || e.event_index === i), true);
assert.equal(events.filter(x => x.event === 'input_adapter_disable_request').length, 1);
assert.equal(events.filter(x => x.event === 'input_adapter_effective_state').length, 3);
console.log('simulated Frida hook contract passed: ' + hooks.size + ' hooks');
"""


class AmberGuideHookMockTests(unittest.TestCase):
    def test_simulated_frida_js_hooks(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js unavailable; ordinary Python static guards still run")
        result = subprocess.run(
            [node, "-e", JS_HOST_TEST, str(PROBE)],
            cwd=ROOT, check=True, text=True, capture_output=True, timeout=20,
        )
        self.assertIn("22 hooks", result.stdout)


if __name__ == "__main__":
    unittest.main()
