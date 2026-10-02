# Xref artifacts

Reusable sender/receiver and type/method relationships belong here.

## Current publication state

The currently committed 7.1 xref datasets are partial evidence seeds:

- `message-handlers.csv`
- `message-senders.csv`
- `message-constructors.csv`

They were recovered from the current-client born audit and related protocol work. Blank type or method identities are allowed when the address/relation itself is supported but the original obfuscated identity has not yet been restored into the shared dataset.

The maintained CSV contracts require stable columns, valid CmdIds/RVAs, valid direction/status values where applicable, and non-empty context/evidence. Ordinary CI validates all three committed tables through `genshinre.xrefartifacts`.

## Future reusable xref surfaces

These names are reserved for broader indexes but are not currently published:

- `method-xrefs.csv`
- `type-xrefs.csv`

Do not treat their absence as missing generated output, and do not create hand-selected files under those names merely to satisfy the target layout. Publish them only when a reusable producer and evidence contract exist.

Store RVA rather than sample VA where possible, and keep context/status/evidence columns so a bare address never becomes an unexplained fact.
