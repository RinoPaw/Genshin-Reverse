# QuestExcel PR #17 read-only audit archive

State: **ARCHIVED** (2026-10-12). These source files are copied byte-for-byte from [`RinoPaw/AstaPS-Resource@ea4dda0a`](https://github.com/RinoPaw/AstaPS-Resource/tree/ea4dda0a6df02f899e9deff27f662d8c5a5eb5b7), before its temporary audit branch was retired. The scripts audit Resource-derived data; they do **not** recover native Genshin 7.1 prerequisites or change any resources.

- [`audit_rino_resource_delta.py`](audit_rino_resource_delta.py) compares two Resource checkouts (full flattened 33,217-row QuestExcel, optional avatar material subset) and reports row/field drift. Original Git blob: `2bc5cf70212ea5a9a331aaf881ca7fb2c07974e2`.
- [`verify_rino_questexcel_handoff.py`](verify_rino_questexcel_handoff.py) compares **five** pinned Resource checkouts (old upstream baseline, PR #17 candidate, historical play/rino QuestExcel, GCResource 3700 and 4000 quest sources). It validates allowed prerequisite-only changes, 35301 Amber safeguards, and 34 historical combiner agreements. Original Git blob: `47b3ba25653a09f60e7b06caf4edfe7ac31415f6`.

Original one-shot CI definitions remain in the immutable investigation commit: [resource delta workflow](https://github.com/RinoPaw/AstaPS-Resource/blob/ea4dda0a6df02f899e9deff27f662d8c5a5eb5b7/.github/workflows/audit-rino-resource-delta.yml) and [QuestExcel handoff workflow](https://github.com/RinoPaw/AstaPS-Resource/blob/ea4dda0a6df02f899e9deff27f662d8c5a5eb5b7/.github/workflows/verify-rino-questexcel-handoff.yml).

Successful original runs: [resource divergence](https://github.com/RinoPaw/AstaPS-Resource/actions/runs/38162752700) and [PR #17 independent handoff](https://github.com/RinoPaw/AstaPS-Resource/actions/runs/38163965154). These are **historic static CI results**, not an ongoing check or a Genshin 7.1 client playthrough.

### Reproduction constraints

Both scripts expect **Resource checkout directories**, not a Genshin-Reverse working directory. The handoff verifier intentionally asserts there are differences between a **pre-merge upstream baseline** (e.g. `1b8854b7fab610981dd2115956f0bceee6503c5c`) and the verified candidate (`0850e6250a6b141d4afe7a9bb91bf50c27f812ea`). Comparing today's upstream `main` against the now-merged candidate will not reproduce the old count; that is expected and **not a regression**. The original play/rino comparison also assumes its old QuestExcel blob. Historical GCResource refs `3700` and `4000` are separate compatibility evidence, not 7.1 native extraction.

The merged production change is [Resource PR #17](https://github.com/MeChen618/AstaPS-Resource/pull/17) at `5ff5f0b083fd3683aca894e4ebc2ba602306820f`: 314 existing rows, only `acceptCond` and `acceptCondComb`; no quest reward, finish logic, or unrelated actions changed. Do not replay the older automated QuestExcel overlay or revert the 35301 safeguard.
