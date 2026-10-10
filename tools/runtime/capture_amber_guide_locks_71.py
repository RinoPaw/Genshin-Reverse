"""Read-only client UI/interaction lock trace for the exact 7.1 Global Windows sample.

Do not use the trace as proof of the absence of pre-attach locks. The launcher
hash-checks the supplied executable; it cannot hash the image inside the game
process, so --exe must point to the same file that is running.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.sampleidentity import require_profile_exe


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Trace native Amber conversation completion, interaction locks, and "
            "newbie UI events on the exact Genshin 7.1 Global Windows client."
        )
    )
    parser.add_argument("--process", default="GenshinImpact.exe")
    parser.add_argument("--exe", type=Path, required=True,
                        help="path to the running 7.1 Global Windows GenshinImpact.exe")
    parser.add_argument("--output", type=Path, default=Path("amber-guide-locks-71.ndjson"))
    parser.add_argument(
        "--script", type=Path,
        default=Path(__file__).with_suffix(".js"),
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="also trace newbie OnNotify and compulsory controller callbacks",
    )
    args = parser.parse_args()

    if not args.exe.is_file():
        raise SystemExit(f"executable not found: {args.exe}")
    if not args.script.is_file():
        raise SystemExit(f"Frida script not found: {args.script}")
    try:
        executable_hash = require_profile_exe(args.exe, PROFILE_71)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        import frida
    except ImportError as exc:
        raise SystemExit(
            "Frida Python bindings are required: python -m pip install frida"
        ) from exc

    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.script.read_text(encoding="utf-8")
    output = args.output.open("a", encoding="utf-8", buffering=1)

    def record(kind: str, payload: object) -> None:
        output.write(json.dumps({
            "timestamp_utc": utc_now(),
            "kind": kind,
            "payload": payload,
        }, ensure_ascii=False, separators=(",", ":")) + "\n")

    record("capture_session", {
        "profile": PROFILE_71.identity,
        "exe": str(args.exe.resolve()),
        "exe_sha256": executable_hash,
        "expected_exe_sha256": PROFILE_71.exe_sha256,
        "process": args.process,
        "script": str(args.script.resolve()),
        "verbose": args.verbose,
        "pre_attach_lock_state": "unknown",
    })

    def on_message(message: dict, data: object) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            record("client_native_event", payload)
            if isinstance(payload, dict):
                if payload.get("ready"):
                    print("Native hooks ready:", payload.get("hook_count"),
                          "module:", payload.get("module"))
                elif "event" in payload:
                    details = " ".join(
                        f"{key}={payload[key]}"
                        for key in ("talk_id", "reason", "guide_name", "accepted",
                                    "mask_index", "compulsory")
                        if key in payload
                    )
                    print(f"{payload.get('elapsed_ms')}ms "
                          f"{payload['event']} {details}")
            return
        record("frida_message", message)
        if message.get("type") == "error":
            print(message.get("stack") or message, file=sys.stderr)

    session = None
    script = None
    try:
        session = frida.attach(args.process)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        config = script.exports_sync.configure(bool(args.verbose))
        if config.get("verbose") != args.verbose:
            raise RuntimeError("Frida guide trace verbosity configuration mismatch")
        record("capture_config", config)
        print("Exact 7.1 executable verified:", executable_hash)
        print("Capturing native events to:", args.output)
        print("Attach before the Amber dialogue to record the matching lock/unlock transitions.")
        print("Press Enter to stop the read-only capture.")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
    finally:
        try:
            if script is not None:
                script.unload()
        finally:
            try:
                if session is not None:
                    session.detach()
            finally:
                output.close()


if __name__ == "__main__":
    main()
