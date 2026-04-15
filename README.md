# Recursive Stwo Bitcoin Verifier

Bitcoin script verification of STARK proofs using the Stwo prover. This repository explores three different approaches to verify recursive proofs on Bitcoin.

## Overview

The goal is to verify a recursive proof chain on Bitcoin. The chain verifies computation through multiple layers:

```
Application (e.g., Fibonacci) 
    → level13-1.bin (PlonkWithPoseidonProof<Poseidon31MerkleHasher>)
    → Bitcoin-verifiable proof
```

Three approaches have been implemented:

| Approach | Branch | Scripts | On-chain Size | Fee | Proof Generation |
|----------|--------|---------|---------------|-----|------------------|
| **Delegation** | `main` | ~131 | ~3 MB | ~1.28M sats | Two proofs required |
| **Alt 1: Direct PlonkWithoutPoseidon** | `alternative-1-pure-sha256` | ~131 | ~3 MB | ~1.28M sats | Single proof, 64+ GB RAM |
| **PlonkWithPoseidon Direct** | `alternative-1-pure-sha256` | ~176 | ~9.5 MB | ~3.5M sats | Single proof |

---

## Approach 1: Delegation (Recommended)

**Branch:** `main`

The original and most practical approach. Uses a two-tier proof system:

1. **Outer proof** (`hybrid_hash.bin`): PlonkWithPoseidon with `Sha256Poseidon31MerkleHasher`
   - Verifies the level13 recursive chain
   - Uses hybrid hasher (Poseidon internally, SHA256 at Merkle roots)
   
2. **Inner proof** (`bitcoin_proof.bin`): PlonkWithoutPoseidon with `Sha256MerkleHasher`
   - Verifies "the outer proof is valid"
   - Only 28 columns (vs 130 in outer proof)

**Why this works well:**
- The hybrid hasher makes the inner circuit SNARK-friendly (Poseidon inside = ~300 constraints/hash vs SHA256 = ~30,000)
- On-chain verification only sees the simpler 28-column structure
- Total on-chain footprint: ~3 MB, ~1.28M sats

**Architecture:**
```
Off-chain:                              On-chain:
┌─────────────────────┐                 ┌─────────────────────┐
│ Outer proof         │                 │ Delegation scripts  │
│ (hybrid_hash.bin)   │ ─────────────▶  │ (5 scripts)         │
│ 130 columns         │                 │ SHA256 Merkle work  │
└─────────────────────┘                 └──────────┬──────────┘
         │                                         │
         │ proves                        delegated inputs
         ▼                                         │
┌─────────────────────┐                 ┌──────────▼──────────┐
│ Inner proof         │                 │ Last scripts        │
│ (bitcoin_proof.bin) │ ─────────────▶  │ (~126 scripts)      │
│ 28 columns          │                 │ Full FRI verify     │
└─────────────────────┘                 └─────────────────────┘
```

### Running

```bash
git checkout main

# Run the covenant test (verifies all scripts work)
cargo test -p recursive-stwo-covenant test_covenant --release

# Expected output: ~131 scripts, ~1.28M sats total fee
```

---

## Approach 2: Direct PlonkWithoutPoseidon (Alternative 1)

**Branch:** `alternative-1-pure-sha256`

Single proof approach using only SHA256, no Poseidon accelerator.

**How it works:**
- Creates a PlonkWithoutPoseidon circuit that verifies level13-1.bin
- Poseidon operations are emulated using arithmetic gates (~30x more expensive)
- Resulting circuit: 2^21 rows

**Trade-offs:**
- Simpler proof chain (single proof)
- Much higher proof generation requirements (64+ GB RAM)
- Same on-chain cost as delegation (~131 scripts)

### Running

```bash
git checkout alternative-1-pure-sha256

# Validate circuit (no proof generation)
cargo run --release -p alt1-proof-generator -- --validation-only

# Generate proof (requires 64+ GB RAM)
cargo run --release -p alt1-proof-generator

# Run covenant test
cargo test -p recursive-stwo-covenant test_covenant --release
```

**Proof generator output:**
```
After proof allocation: 307 rows
After Fiat-Shamir: 69,138 rows
After Composition: 71,195 rows  
After Answer: 479,056 rows
After Folding: 1,369,882 rows
Final circuit log_size: 21 (2,097,152 rows)
```

---

## Approach 3: PlonkWithPoseidon Direct Verification

**Branch:** `alternative-1-pure-sha256` (in `last/src/script/plonk_with_poseidon/`)

Directly verify a PlonkWithPoseidon proof on Bitcoin without delegation.

**How it works:**
- Creates Bitcoin scripts that verify the 130-column PlonkWithPoseidon proof structure
- No intermediate proof layer
- Scripts handle both PLONK and Poseidon sub-circuits

**Structure (130 columns):**
- Preprocessed: 50 (10 PLONK + 40 Poseidon)
- Trace: 60 (12 PLONK + 48 Poseidon)
- Interaction: 16 (8 PLONK + 8 Poseidon)
- Composition: 4

**Trade-offs:**
- Single proof, simpler proof chain
- ~3x larger on-chain footprint (176 scripts, ~9.5 MB)
- ~3x higher fees (~3.5M sats)

### Running

```bash
git checkout alternative-1-pure-sha256

# Run PlonkWithPoseidon verification tests
cargo test -p recursive-stwo-last -- script::plonk_with_poseidon --release

# Run complete verification summary
cargo test -p recursive-stwo-last -- test_complete_verification_summary --release

# Run global scripts test
cargo test -p recursive-stwo-last -- test_e2e_global_scripts_simulation --release
```

---

## Data Files

| File | Description | Size |
|------|-------------|------|
| `data/hybrid_hash.bin` | Outer PlonkWithPoseidon proof (delegation) | 80 KB |
| `data/bitcoin_proof.bin` | Inner PlonkWithoutPoseidon proof (delegation) | 101 KB |
| `data/alternative1_proof.bin` | Direct PlonkWithoutPoseidon proof (Alt 1) | 99 KB |
| `data/poseidon_accelerated_proof.bin` | PlonkWithPoseidon proof for direct verification | 80 KB |
| `data/precomputed_tree.bin` | Precomputed lookup table | 8 MB |

---

## Repository Structure

```
recursive-stwo-bitcoin/
├── bitcoin_dsl/          # Bitcoin script DSL
├── primitives/           # Field arithmetic, Poseidon, etc.
├── last/                 # Bitcoin script verifier
│   └── src/script/
│       ├── global/       # Global scripts (Fiat-Shamir, coset vanishing, etc.)
│       ├── per_query/    # Per-query scripts (domain points, FRI folding)
│       └── plonk_with_poseidon/  # PlonkWithPoseidon direct verification
├── delegation/           # Delegation scripts (extract from outer proof)
├── covenant/             # Bitcoin covenant integration
├── proof_generator/      # Original proof generator
├── alt1_proof_generator/ # Alternative 1 proof generator
└── poseidon_proof_generator/  # PlonkWithPoseidon proof generator
```

---

## Dependencies

- Rust 1.75+
- [stwo-prover](https://github.com/Bitcoin-Wildlife-Sanctuary/stwo-circle-poseidon-plonk/) (cp-poseidon-flattened branch)
- [recursive-stwo](https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo) (rev caea77f)
- [covenants-gadgets](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets) (tag 1.1.1)

For local development, clone stwo-circle-poseidon-plonk alongside this repo:
```bash
cd ..
git clone https://github.com/Bitcoin-Wildlife-Sanctuary/stwo-circle-poseidon-plonk/
cd stwo-circle-poseidon-plonk
git checkout cp-poseidon-flattened
```

---

## Conclusion

The **delegation approach** (main branch) is recommended for production use:
- Proven to work
- Smallest on-chain footprint
- Acceptable off-chain overhead (two proof generation steps)

The other approaches demonstrate alternatives:
- **Alt 1** proves a single-proof approach is possible but requires significant compute resources
- **PlonkWithPoseidon Direct** shows the cost of verifying the full 130-column structure on-chain

---

## License

See LICENSE file.
