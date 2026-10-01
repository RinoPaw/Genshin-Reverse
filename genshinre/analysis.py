from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def research_status(version_path: Path) -> dict[str, object]:
    analyses_path = version_path / "analyses"
    topics: list[dict[str, object]] = []
    legacy_without_evidence: list[str] = []
    state_counts: Counter[str] = Counter()
    claim_status_counts: Counter[str] = Counter()

    if not analyses_path.exists():
        return {
            "version_path": str(version_path),
            "topic_count": 0,
            "state_counts": {},
            "claim_status_counts": {},
            "topics": [],
            "legacy_without_evidence": [],
        }

    for topic_dir in sorted(path for path in analyses_path.iterdir() if path.is_dir()):
        evidence_path = topic_dir / "evidence.json"
        if not evidence_path.exists():
            legacy_without_evidence.append(topic_dir.name)
            continue
        try:
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"cannot read {evidence_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{evidence_path}: root must be an object")

        state = str(data.get("state", ""))
        state_counts[state] += 1
        per_topic_counts: Counter[str] = Counter()
        open_claims: list[dict[str, str]] = []
        for claim in data.get("claims", []):
            if not isinstance(claim, dict):
                continue
            status = str(claim.get("status", ""))
            claim_status_counts[status] += 1
            per_topic_counts[status] += 1
            if status in {"HIGH_CONFIDENCE", "CANDIDATE", "UNRESOLVED"}:
                open_claims.append(
                    {
                        "id": str(claim.get("id", "")),
                        "status": status,
                        "statement": str(claim.get("statement", "")),
                    }
                )

        topics.append(
            {
                "topic": str(data.get("topic", topic_dir.name)),
                "state": state,
                "path": str(evidence_path.relative_to(version_path)),
                "claim_counts": dict(sorted(per_topic_counts.items())),
                "open_claims": open_claims,
                "next_steps": data.get("next_steps", []),
            }
        )

    return {
        "version_path": str(version_path),
        "topic_count": len(topics),
        "state_counts": dict(sorted(state_counts.items())),
        "claim_status_counts": dict(sorted(claim_status_counts.items())),
        "topics": topics,
        "legacy_without_evidence": legacy_without_evidence,
    }
