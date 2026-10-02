from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Attach the maintained Genshin 7.1 Frida probe, print decrypted packet headers, "
            "and preserve the capture as newline-delimited JSON."
        )
    )
    parser.add_argument("--process", default="GenshinImpact.exe")
    parser.add_argument(
        "--exe",
        type=Path,
        required=True,
        help="exact GenshinImpact.exe to hash before attaching; must match the pinned global 7.1 sample",
    )
    parser.add_argument("--output", type=Path, default=Path("game-packets-71.ndjson"))
    parser.add_argument(
        "--script",
        type=Path,
        default=Path(__file__).with_name("capture_game_packets_71.js"),
    )
    args = parser.parse_args()

    if not args.exe.is_file():
        raise SystemExit(f"executable does not exist: {args.exe}")
    exe_sha256 = sha256_file(args.exe)
    if exe_sha256.lower() != EXPECTED_EXE_SHA256:
        raise SystemExit(
            "refusing to attach with build-specific RVAs: executable SHA-256 mismatch\n"
            f"expected: {EXPECTED_EXE_SHA256}\n"
            f"actual:   {exe_sha256}\n"
            f"file:     {args.exe}"
        )

    try:
        import frida
    except ImportError as exc:
        raise SystemExit(
            "Frida Python bindings are required for this runtime-only probe. "
            "Install them with: python -m pip install frida"
        ) from exc

    source = args.script.read_text(encoding="utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = args.output.open("a", encoding="utf-8", buffering=1)

    def record(kind: str, payload: object) -> None:
        row = {"timestamp_utc": utc_now(), "kind": kind, "payload": payload}
        output.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    record(
        "capture_session",
        {
            "process": args.process,
            "exe": str(args.exe.resolve()),
            "exe_sha256": exe_sha256,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "build_verified": True,
            "script": str(args.script.resolve()),
        },
    )

    def on_message(message, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            record("packet_probe", payload)
            if isinstance(payload, dict):
                if payload.get("ready"):
                    print(
                        "probe ready:",
                        payload.get("module_base"),
                        "S2C", payload.get("s2c_post_xor_rva"),
                        "C2S", payload.get("c2s_pre_xor_rva"),
                    )
                elif "cmd_id" in payload:
                    marker = " WATCH" if payload.get("watched") else ""
                    print(
                        f"{payload.get('direction','?'):>3} "
                        f"cmd={payload['cmd_id']:>5} "
                        f"frame={payload.get('frame_size')} "
                        f"head={payload.get('head_size')} "
                        f"body={payload.get('body_size')}{marker}"
                    )
                elif payload.get("capture_error"):
                    print("capture error:", payload["capture_error"], file=sys.stderr)
            return

        record("frida_message", message)
        if message.get("type") == "error":
            print(message.get("stack") or message, file=sys.stderr)

    session = frida.attach(args.process)
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    print(f"verified global 7.1 executable: {exe_sha256}")
    print(f"capturing {args.process} -> {args.output}")
    print("trigger one genuine teleport-point unlock; press Enter when the narrow window is captured")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        try:
            script.unload()
        finally:
            session.detach()
            output.close()


if __name__ == "__main__":
    main()
