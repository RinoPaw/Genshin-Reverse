"""Summarize the read-only 7.1 Amber guide/input trace without inventing causes.

The capture records native callbacks, not complete client state or a replay.
Absence of a hook event cannot prove a call never occurred before attachment.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path


GUIDE_EVENTS = {
    "start_guide", "guide_start_predicate_result", "guide_start_dispatch",
    "end_guide", "set_newbie_mask_index", "set_newbie_mask_compulsory",
    "newbie_setup_view", "newbie_on_notify", "newbie_compulsory_controller",
}
INPUT_EVENTS = {
    "lock_inter", "unlock_inter", "input_adapter_disable_request",
    "input_adapter_effective_state", "actor_utils_set_ui_lock_state",
    "base_actor_enable_player_input", "actor_utils_enable_player_input",
    "actor_utils_enable_input_by_quest",
    "actor_utils_set_quest_dialog_enable", "stop_local_avatar",
}


def split_sessions(path: Path) -> list[dict]:
    """Append-mode traces may contain multiple sessions; never merge their locks."""
    sessions: list[dict] = []
    current: dict | None = None
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            # Do not quietly treat a truncated capture as a complete one.
            if current is None:
                current = {"metadata": {}, "events": [], "errors": []}
            current["errors"].append(f"line {line_no}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(item, dict):
            if current is None:
                current = {"metadata": {}, "events": [], "errors": []}
            current["errors"].append(f"line {line_no}: non-object record")
            continue
        kind = item.get("kind")
        if kind == "capture_session":
            if current is not None:
                sessions.append(current)
            current = {"metadata": item.get("payload", {}), "events": [], "errors": []}
            continue
        if current is None:
            current = {"metadata": {}, "events": [], "errors": ["missing capture_session record"]}
        payload = item.get("payload")
        if kind == "client_native_event":
            if isinstance(payload, dict):
                current["events"].append(payload)
            else:
                current["errors"].append(f"line {line_no}: invalid native event")
        elif kind == "frida_message":
            if not isinstance(payload, dict):
                current["errors"].append(f"line {line_no}: invalid Frida message")
            elif payload.get("type") == "error":
                current["errors"].append(f"line {line_no}: Frida script error")
        elif kind == "capture_config":
            current["config"] = payload
        else:
            current["errors"].append(f"line {line_no}: unknown record kind {kind!r}")
    if current is not None:
        sessions.append(current)
    return sessions


def summarize_session(session: dict) -> dict:
    events = session["events"]
    ready = [e for e in events if e.get("ready") is True]
    native = [e for e in events if isinstance(e.get("event"), str)]
    names = Counter(e["event"] for e in native)
    handoff = next(
        (i for i, e in enumerate(native)
         if e["event"] == "finish_curr_talk" and e.get("talk_id") == 35601),
        None,
    )
    phase = lambda i: "before_35601_finish_callback" if handoff is not None and i < handoff else (
        "at_or_after_35601_finish_callback" if handoff is not None else "unanchored"
    )
    timeline = [
        {key: v for key, v in {
            "event_index": e.get("event_index"),
            "elapsed_ms": e.get("elapsed_ms"),
            "thread_id": e.get("thread_id"),
            "phase": phase(i),
            "event": e["event"],
            "guide_name": e.get("guide_name"),
            "accepted": e.get("accepted"),
            "reason": e.get("reason"),
            "adapter_id": e.get("adapter_id"),
            "requested_flag": e.get("requested_flag"),
            "numeric_source": e.get("numeric_source"),
            "disabled": e.get("disabled"),
            "disable_mask": e.get("disable_mask"),
            "ui_locked": e.get("ui_locked"),
            "enabled": e.get("enabled"),
            "mask_index": e.get("mask_index"),
            "compulsory": e.get("compulsory"),
        }.items() if v is not None or key in ("event_index", "event", "phase")}
        for i, e in enumerate(native) if e["event"] in GUIDE_EVENTS | INPUT_EVENTS
    ]
    # A set of witnessed, unmatched calls is not the native InteractionManager's
    # _lockedReasonSet: attachment may have happened after earlier LockInter calls.
    witnessed_locks: set[int] = set()
    last_adapter_state: dict[str, dict] = {}
    latest_ui_lock = None
    for e in native:
        name = e["event"]
        reason = e.get("reason")
        if name == "lock_inter" and isinstance(reason, int):
            witnessed_locks.add(reason)
        elif name == "unlock_inter" and isinstance(reason, int):
            witnessed_locks.discard(reason)
        elif name == "input_adapter_effective_state":
            adapter_id = e.get("adapter_id")
            if isinstance(adapter_id, int):
                last_adapter_state[str(adapter_id)] = {
                    "disabled": e.get("disabled"),
                    "disable_mask": e.get("disable_mask"),
                    "event_index": e.get("event_index"),
                }
        elif name == "actor_utils_set_ui_lock_state":
            latest_ui_lock = e.get("ui_locked")
    rejected = [
        {"guide_name": e.get("guide_name"), "event_index": e.get("event_index")}
        for e in native
        if e["event"] == "guide_start_predicate_result" and e.get("accepted") is False
    ]
    issues = list(session["errors"])
    if len(ready) != 1:
        issues.append(f"expected one native ready event, observed {len(ready)}")
    if handoff is None:
        issues.append("FinishCurrTalk(35601) not observed; capture may not include the handoff")
    if not session.get("config"):
        issues.append("capture_config absent; probe configuration unverified")
    findings = []
    if rejected:
        findings.append("A guide predicate rejected at least one name; investigate its matching dispatch/other guides.")
    if not names["start_guide"]:
        findings.append("StartGuide not observed; absence cannot prove it never ran.")
    if not names["set_newbie_mask_compulsory"] and not names["set_newbie_mask_index"]:
        findings.append("BlackMask control calls not observed; no conclusion about rendering.")
    if witnessed_locks:
        findings.append("Some observed InteractionManager lock calls lack a matching observed unlock; actual prior state unknown.")
    if any(state.get("disabled") is True for state in last_adapter_state.values()):
        findings.append("At least one native input adapter's latest observed state is disabled; this is not global input state.")
    return {
        "profile": session.get("metadata", {}).get("profile"),
        "hook_ready": len(ready) == 1,
        "hook_count": ready[0].get("hook_count") if ready else None,
        "observed_finish_35601": handoff is not None,
        "event_counts": dict(sorted(names.items())),
        "guide_predicate_rejections": rejected,
        "observed_unpaired_interaction_reasons": sorted(witnessed_locks),
        "latest_adapter_states": last_adapter_state,
        "latest_ui_lock_argument": latest_ui_lock,
        "timeline": timeline,
        "capture_warnings": issues,
        "interpretation_limits": [
            "Historical quest 35601 may lock input before its dialogue; attach before quest start.",
            "Native hook events are observations, not proof of complete client lock/guide state.",
            "Mask setter calls do not prove the BlackMask was rendered.",
            "Quest-list receiver does not prove quest 35603 was present in its payload.",
            "No result here independently establishes the cause of the stuck client.",
        ],
        "findings": findings,
    }


def analyze(path: Path) -> dict:
    sessions = split_sessions(path)
    return {"session_count": len(sessions),
            "sessions": [summarize_session(session) for session in sessions]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze 7.1 Amber read-only native event capture")
    parser.add_argument("capture", type=Path, help="NDJSON produced by capture_amber_guide_locks_71.py")
    parser.add_argument("--output", type=Path, help="write JSON report instead of stdout")
    args = parser.parse_args()
    report = json.dumps(analyze(args.capture), ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
