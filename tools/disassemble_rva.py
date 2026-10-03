from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from genshinre.pe import PEImage


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def disassemble_rva(
    exe: Path,
    rva: int,
    size: int,
    *,
    expected_sha256: str | None = None,
    label: str = "",
) -> dict[str, object]:
    if rva < 0:
        raise ValueError("RVA must be non-negative")
    if size <= 0:
        raise ValueError("size must be positive")

    exe_sha256 = _sha256(exe)
    if expected_sha256 is not None and exe_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            "unexpected executable SHA-256: "
            f"{exe_sha256} != {expected_sha256.lower()}"
        )

    with PEImage(exe) as image:
        code = image.read_rva(rva, size)
        if len(code) != size:
            raise ValueError(
                f"truncated RVA read at 0x{rva:X}: expected {size} bytes, got {len(code)}"
            )
        image_base = image.image_base

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions: list[dict[str, object]] = []
    decoded_bytes = 0
    for insn in md.disasm(code, image_base + rva):
        insn_rva = insn.address - image_base
        instructions.append(
            {
                "rva": f"0x{insn_rva:X}",
                "va": f"0x{insn.address:X}",
                "size": insn.size,
                "bytes": bytes(insn.bytes).hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
        )
        decoded_bytes += insn.size

    return {
        "label": label,
        "exe": str(exe),
        "exe_sha256": exe_sha256,
        "image_base": f"0x{image_base:X}",
        "start_rva": f"0x{rva:X}",
        "end_rva": f"0x{rva + size:X}",
        "size": size,
        "instruction_count": len(instructions),
        "decoded_bytes": decoded_bytes,
        "trailing_bytes": code[decoded_bytes:].hex(),
        "instructions": instructions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Disassemble an RVA range from a PE image with Capstone."
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("rva", type=lambda text: int(text, 0))
    parser.add_argument("size", type=lambda text: int(text, 0))
    parser.add_argument("--expected-sha256")
    parser.add_argument("--label", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = disassemble_rva(
        args.exe,
        args.rva,
        args.size,
        expected_sha256=args.expected_sha256,
        label=args.label,
    )
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
