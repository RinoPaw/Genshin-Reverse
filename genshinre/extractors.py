from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .dumpcs import import_dump_cs
from .fingerprint import fingerprint


def run_mhydump(
    exe: Path,
    metadata: Path,
    output_dir: Path,
    executable: str = "mhydump",
    tool_revision: str = "",
    keep_dump_cs: Path | None = None,
) -> dict[str, object]:
    resolved = shutil.which(executable) if not Path(executable).exists() else executable
    if not resolved:
        raise FileNotFoundError(
            f"cannot find {executable!r}; build/install an mhydump-compatible extractor first"
        )

    sample_provenance = {
        "GenshinImpact.exe": fingerprint(exe),
        "global-metadata.dat": fingerprint(metadata),
    }

    def run_to(dump_path: Path) -> dict[str, object]:
        dump_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(resolved),
            "dump",
            "--exe",
            str(exe),
            "--metadata",
            str(metadata),
            "--out",
            str(dump_path),
        ]
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        if process.returncode != 0:
            raise RuntimeError(
                "mhydump failed with exit code "
                f"{process.returncode}\nstdout:\n{process.stdout[-4000:]}\nstderr:\n{process.stderr[-4000:]}"
            )
        summary = import_dump_cs(
            dump_path,
            output_dir,
            source_tool="mhydump",
            tool_revision=tool_revision,
            provenance={
                "samples": sample_provenance,
                "command": command,
            },
        )
        return {
            "extractor": "mhydump",
            "tool_revision": tool_revision,
            "command": command,
            "stdout_tail": process.stdout[-2000:],
            "stderr_tail": process.stderr[-2000:],
            "metadata": summary,
        }

    if keep_dump_cs is not None:
        result = run_to(keep_dump_cs)
    else:
        with tempfile.TemporaryDirectory(prefix="genshinre-") as td:
            result = run_to(Path(td) / "dump.cs")

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "extractor.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return result
