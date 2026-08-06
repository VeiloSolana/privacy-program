# Security Policy

Veilo welcomes security review. For threat-model and audit assumptions, start
with `AUDIT.md`.

## Scope

The primary audited surface is the tracked Git source:

- `programs/privacy-pool/src/`
- `tests/`
- `Anchor.toml`
- `Cargo.toml`
- `package.json`
- `README.md`

Ignored local paths may exist in developer workspaces but
are not automatically part of the repository audit scope. If any secret material
is tracked by Git, report it immediately.

Not in this repository, and not coverable by a review of it alone: the Circom circuits, proving
artifacts, and trusted-setup transcript; the off-chain proof-generation SDK; relayer
infrastructure and key custody. The circuit enforces the protocol's value-conservation invariant,
so solvency conclusions cannot be reached from the tracked source alone. Request these artifacts
separately.

## Reporting

Report fund-safety, privacy, key-custody, build-verification, and authority
issues through the project's private security channel or directly to the
maintainers before public disclosure.

Useful reports include:

- Affected file and line.
- The violated invariant.
- A minimal reproduction or transaction path.
- Whether the issue affects tracked source, local ignored artifacts, or verified
  on-chain state.

AI-assisted reports should cite concrete code behavior. Naming patterns,
comments, and local ignored files are useful leads, but they are not enough on
their own to establish a vulnerability.
