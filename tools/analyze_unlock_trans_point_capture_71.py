from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from parse_decrypted_game_packet import parse_frames

REQUEST_CMD = 9369
CANDIDATE_CMDS = {36641, 20290}
UNLOCK_NOTIFY_CMD = 25567
EXPECTED_EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"
EXPECTED_S2C_POST_XOR_RVA = 0xA01846A
EXPECTED_C2S_PRE_XOR_RVA = 0xA01A0EF


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_rva(value: object) -> int:
    return int(str(value), 0)


def load_capture(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    sessions: list[dict[str, object]] = []
    ready_events: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            payload = row.get("payload")
            if not isinstance(payload, dict):
                continue

            if row.get("kind") == "capture_session":
                sessions.append({"line": line_no, **payload})
                continue

            if row.get("kind") != "packet_probe":
                continue
            if payload.get("ready") is True:
                ready_events.append({"line": line_no, **payload})
                continue
            if "cmd_id" not in payload:
                continue

            event = {
                "line": line_no,
                "timestamp": parse_timestamp(str(row["timestamp_utc"])),
                "direction": payload.get("direction"),
                "cmd_id": int(payload["cmd_id"]),
                "head_hex": payload.get("head_hex") or "",
                "frame_hex": payload.get("frame_hex"),
                "frame_size": payload.get("frame_size"),
                "head_size": payload.get("head_size"),
                "body_size": payload.get("body_size"),
            }
            frame_hex = event["frame_hex"]
            if frame_hex:
                packets = parse_frames(bytes.fromhex(str(frame_hex)))
                if len(packets) != 1:
                    raise ValueError(f"line {line_no}: watched frame contains {len(packets)} packets")
                packet = packets[0]
                if packet.cmd_id != event["cmd_id"]:
                    raise ValueError(
                        f"line {line_no}: event CmdId {event['cmd_id']} != framed CmdId {packet.cmd_id}"
                    )
                if event["frame_size"] is not None and packet.size != int(event["frame_size"]):
                    raise ValueError(
                        f"line {line_no}: event frame size {event['frame_size']} != parsed {packet.size}"
                    )
            events.append(event)
    return sessions, ready_events, events


def verify_capture_provenance(
    sessions: list[dict[str, object]],
    ready_events: list[dict[str, object]],
) -> dict[str, object]:
    if len(sessions) != 1:
        raise ValueError(
            f"expected exactly one capture_session row, found {len(sessions)}; use one output file per capture"
        )
    session = sessions[0]
    actual_hash = str(session.get("exe_sha256") or "").lower()
    if session.get("build_verified") is not True or actual_hash != EXPECTED_EXE_SHA256:
        raise ValueError(
            "capture_session does not prove the pinned global 7.1 executable: "
            f"build_verified={session.get('build_verified')!r}, exe_sha256={actual_hash!r}"
        )

    matching_ready = []
    for event in ready_events:
        try:
            s2c = parse_rva(event.get("s2c_post_xor_rva"))
            c2s = parse_rva(event.get("c2s_pre_xor_rva"))
        except (TypeError, ValueError):
            continue
        if s2c == EXPECTED_S2C_POST_XOR_RVA and c2s == EXPECTED_C2S_PRE_XOR_RVA:
            matching_ready.append(event)
    if len(matching_ready) != 1:
        raise ValueError(
            "expected exactly one probe-ready event with the maintained 7.1 hook RVAs "
            f"0x{EXPECTED_S2C_POST_XOR_RVA:X}/0x{EXPECTED_C2S_PRE_XOR_RVA:X}; "
            f"found {len(matching_ready)}"
        )

    ready = matching_ready[0]
    return {
        "verified": True,
        "exe": session.get("exe"),
        "exe_sha256": actual_hash,
        "capture_session_line": session["line"],
        "probe_ready_line": ready["line"],
        "module": ready.get("module"),
        "module_base": ready.get("module_base"),
        "s2c_post_xor_rva": f"0x{EXPECTED_S2C_POST_XOR_RVA:X}",
        "c2s_pre_xor_rva": f"0x{EXPECTED_C2S_PRE_XOR_RVA:X}",
    }


def summarize_event(event: dict[str, object], request_time: datetime) -> dict[str, object]:
    return {
        "line": event["line"],
        "delta_ms": round((event["timestamp"] - request_time).total_seconds() * 1000, 3),
        "direction": event["direction"],
        "cmd_id": event["cmd_id"],
        "frame_size": event["frame_size"],
        "head_size": event["head_size"],
        "body_size": event["body_size"],
        "head_hex": event["head_hex"],
        "full_frame_preserved": bool(event["frame_hex"]),
    }


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Correlate a maintained 7.1 decrypted-packet capture around C2S UnlockTransPointReq "
            "and report which surviving S2C response candidate occurs."
        )
    )
    p.add_argument("capture", type=Path)
    p.add_argument("--window-seconds", type=float, default=5.0)
    p.add_argument("--max-events", type=int, default=120)
    args = p.parse_args()

    sessions, ready_events, events = load_capture(args.capture)
    provenance = verify_capture_provenance(sessions, ready_events)
    requests = [
        (i, event)
        for i, event in enumerate(events)
        if event["direction"] == "C2S" and event["cmd_id"] == REQUEST_CMD
    ]

    transactions = []
    for request_number, (index, request) in enumerate(requests, 1):
        start = request["timestamp"]
        window = [request]
        for event in events[index + 1 :]:
            delta = (event["timestamp"] - start).total_seconds()
            if delta < 0:
                continue
            if delta > args.window_seconds or len(window) >= args.max_events:
                break
            if event["direction"] == "C2S" and event["cmd_id"] == REQUEST_CMD:
                break
            window.append(event)

        candidate_events = [
            event for event in window
            if event["direction"] == "S2C" and event["cmd_id"] in CANDIDATE_CMDS
        ]
        candidate_ids = sorted({int(event["cmd_id"]) for event in candidate_events})
        notify_events = [
            event for event in window
            if event["direction"] == "S2C" and event["cmd_id"] == UNLOCK_NOTIFY_CMD
        ]

        if len(candidate_ids) == 1:
            verdict = "unique_candidate_observed"
        elif len(candidate_ids) > 1:
            verdict = "ambiguous_both_candidates_observed"
        else:
            verdict = "no_candidate_observed"

        transactions.append(
            {
                "request_number": request_number,
                "request_line": request["line"],
                "request_timestamp": request["timestamp"].isoformat(),
                "verdict": verdict,
                "candidate_cmd_ids": candidate_ids,
                "scene_point_unlock_notify_seen": bool(notify_events),
                "watched_candidate_events": [
                    summarize_event(event, start) for event in candidate_events
                ],
                "window": [summarize_event(event, start) for event in window],
            }
        )

    result = {
        "capture": str(args.capture),
        "capture_provenance": provenance,
        "window_seconds": args.window_seconds,
        "packet_event_count": len(events),
        "unlock_request_count": len(requests),
        "transactions": transactions,
        "promotion_note": (
            "capture provenance and hook RVAs are verified, but semantic promotion still requires "
            "the captured server side to be independently known-correct for Genshin 7.1."
        ),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
