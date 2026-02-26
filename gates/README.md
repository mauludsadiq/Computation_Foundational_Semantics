# Freeze Gates (Pinned Expected Digests)

This directory contains pinned, hard-expected digests for the spine demo.

## Generate / Update

From repo root:

1) Recompute and write `gates/expected.json`:

cargo run -p collapse_spine_demo -- --freeze

2) Run the freeze gate:

cargo test -p gates

## What is pinned

`expected.json` pins:
- asc7_hash
- domain_digest
- tests_hash
- sembit_hash
- chain_hash

Any change to:
- ASC7 profile compilation rules,
- StructuralNumbers domain construction,
- SemBits test IDs or quotient computation,
- Canonical serialization / hashing,

must intentionally update `gates/expected.json` by re-running the freeze step.
