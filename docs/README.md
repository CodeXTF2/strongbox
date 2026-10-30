# Strongbox documentation

Read in this order:

| # | Document | Read it for |
|---|---|---|
| 1 | [deniable-drives.md](deniable-drives.md) | The design and the spec: threat model (§1), hardware assumptions (§2), key derivations (§5), on-disk formats (§6), routes and the sealed channel (§8), client behaviour (§9). Read the relevant section before touching crypto, formats or server storage. |
| 2 | [server-plan.md](server-plan.md) | What the server stores and sees, the properties it already enforces, the hardening backlog (§3) and the metadata that still leaks (§4). |

`images/` holds the screenshots used by the top-level [README](../README.md).

When a change affects the threat model, a format, a route or a transfer, update the spec here
(and the README diagram if the flow changes).
