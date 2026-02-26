# Computation Foundational Semantics
ASC7 × SemBits × Structural Numbers — a single deterministic, cryptographically-auditable spine in Rust.

This workspace is a **small, fully explicit kernel** that ties together three components:

1) **ASC7** — a hash-certified ASCII collapse/normalization kernel (DSU over printable ASCII with syntax-role constraints).  
2) **SemBits** — semantic entropy via test families, yielding deterministic quotients (partitions) of a domain.  
3) **Structural Numbers (QE)** — explicit finite domains of reduced rationals (ℚ_E bounded) with canonical hashing.

The output of the system is a **chain hash** that pins:
- the ASC7 kernel identity,
- the bounded structural domain identity,
- the SemBits test family identity,
- the resulting quotient identity.

Everything is deterministic:
- canonical serialization (stable ordering via `BTreeMap`),
- SHA-256 over canonical bytes,
- no floats in cert payloads (entropy stored as scaled integer if you add it to payloads).

---

## Repository layout

```
Computation_Foundational_Semantics/
  Cargo.toml                 # workspace
  crates/
    collapse_core/           # canonical bytes + sha256 + cert chain
    asc7/                    # ASCII collapse kernel
    sembit/                  # semantic tests + quotients + digests
    structural_numbers/      # bounded QE domain + domain digest
  bins/
    collapse_spine_demo/     # demo CLI printing stable digests + chain hash
  tests/
    gate_invariants.rs       # deterministic invariants ("gates")
```

---

## Requirements

- Rust toolchain (stable): https://rustup.rs
- Optional: VS Code + rust-analyzer extension

---

## Build and run (terminal)

From the repo root:

### 1) Run the demo
```sh
cargo run -p collapse_spine_demo
```

You should see:
- an ASC7 normalization example
- `asc7_hash`, `domain_digest`, `tests_hash`, `sembit_hash`, `chain_hash`

These values are stable across runs **as long as the code is unchanged**.

### 2) Run the gate tests
```sh
cargo test
```

The gates currently enforce:
- ASC7 idempotence (`K(K(s)) = K(s)`) and terminal verification (`s ∈ W*`)
- chain hash depends on upstream hashes (changing ASC7 hash changes chain hash)
- all core hashes are valid hex digests of length 64

If you want “freeze gates” (exact expected digests), you can:
1. run the demo once
2. copy the printed hashes
3. assert equality against those constants in `tests/gate_invariants.rs`

---

## Using VS Code (VSC)

1. Open VS Code
2. **File → Open Folder…** and select the repo root folder
3. Install the **rust-analyzer** extension (recommended)
4. Use the integrated terminal (**Terminal → New Terminal**) and run:

```sh
cargo test
cargo run -p collapse_spine_demo
```

---

## Design: the connecting spine (how the dots connect)

### A) ASC7 provides *certified text normalization*
ASC7 turns arbitrary printable ASCII input `Σ*` into a smaller witness alphabet `W*` by:
- unioning confusable characters using DSU,
- respecting `syntax_strict` role constraints (delimiters don’t merge with letters/digits),
- choosing deterministic class representatives (`pick_rep`),
- producing a hash (`graph_hash`) that certifies the collapse graph.

This makes every downstream ID string stable (no ambiguity).

### B) Structural Numbers provides a deterministic domain `D`
`structural_numbers::domain_qe_bounded(nmax, dmax)` enumerates reduced rationals:
- `den ∈ [1..=dmax]`, `num ∈ [-nmax..=nmax]`
- normalized by gcd
- sorted + deduped
- hashed via canonical encoding: `domain_digest_hex(domain)`

This produces a reproducible “finite universe” for analysis.

### C) SemBits builds a quotient `Q = D / ~`
SemBits defines a test family `T = [t1, t2, ...]` where each test returns `bool`.
Each element `x ∈ D` gets a signature bit-vector `sig(x)`, and SemBits returns:
- `Quotient` = a map `Signature -> members`
- `H_sem = log2(|classes|)` (computed deterministically)

SemBits digests include:
- `tests_hash_hex(tf, impl_tag)` (ID list + implementation tag)
- `quotient_digest_hex(q)` (signature + count for each class)

### D) Cert chain binds everything
The demo builds:
- ASC7 cert → hash
- SemBits cert embeds ASC7 hash + domain digest + tests hash + quotient digest
- chain hash commits the ordered list `[("asc7", ...), ("sembit", ...)]`

---

## Sharing and cloning

### Share via GitHub (recommended)
1. Create a new repo on GitHub (empty).
2. In this repo folder:

```sh
git init
git add .
git commit -m "Initial: Computation Foundational Semantics (ASC7 + SemBits + QE)"
git branch -M main
git remote add origin <YOUR_GITHUB_REPO_URL>
git push -u origin main
```

Then anyone can clone:
```sh
git clone <YOUR_GITHUB_REPO_URL>
cd Computation_Foundational_Semantics
cargo test
cargo run -p collapse_spine_demo
```

### Share as a zip (offline)
From the parent directory:

```sh
zip -r Computation_Foundational_Semantics.zip Computation_Foundational_Semantics
```

Recipients unzip and run the same cargo commands.

---

## Extending (next step without changing the spine)

- Add new Structural domains (e.g., `Z_E`, `N_E`), keep `domain_digest_hex`.
- Add richer SemBits tests (non-binary) by extending `Signature` variants.
- Add Unicode confusables by introducing a *separate kernel* (new cert + hash), and
  embedding that hash upstream of SemBits (same chain discipline).

The spine stays: **canonical bytes → SHA-256 → certified kernel → chain hash**.
