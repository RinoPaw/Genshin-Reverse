# Xref artifacts

Reusable sender/receiver and type/method relationships belong here.

Canonical outputs:

- `message-handlers.csv`
- `message-senders.csv`
- `message-constructors.csv`
- `method-xrefs.csv`
- `type-xrefs.csv`

The currently committed handler/sender/constructor tables are partial seeds recovered from the 7.1 born audit. Blank identities mean the address/relation is supported while the original obfuscated type or method name has not yet been restored into the shared dataset.

Store RVA rather than sample VA where possible, and keep context/status/evidence columns so a bare address never becomes an unexplained fact.
