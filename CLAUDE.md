# Project Memory: Recursive Stwo Bitcoin Verifier

## Overview

This project implements Bitcoin script verification of STARK proofs using the Stwo prover. It verifies recursive proof chains (e.g., Fibonacci computation) on Bitcoin.

## Three Verification Approaches

### 1. Delegation (Recommended) - `main` branch
- **Two-tier proof system**: Outer PlonkWithPoseidon (hybrid hasher) → Inner PlonkWithoutPoseidon (SHA256)
- **Key insight**: Hybrid hasher (`Sha256Poseidon31MerkleHasher`) makes recursion practical
  - Poseidon internally (~300 constraints/hash) vs SHA256 (~30,000 constraints/hash)
  - Only Merkle roots use SHA256 for Bitcoin compatibility
- **Stats**: ~131 scripts, ~3 MB on-chain, ~1.28M sats fee
- **Files**: `delegation/` module extracts delegated inputs, `last/` module verifies inner proof

### 2. Alternative 1: Direct PlonkWithoutPoseidon - `alternative-1-pure-sha256` branch
- Single proof using emulated Poseidon (no accelerator)
- Circuit size: 2^21 rows, requires 64+ GB RAM for proof generation
- Same on-chain cost as delegation (~131 scripts)
- **Files**: `alt1_proof_generator/`

### 3. PlonkWithPoseidon Direct - `alternative-1-pure-sha256` branch
- Directly verify 130-column PlonkWithPoseidon proof on Bitcoin
- **Stats**: ~176 scripts, ~9.5 MB on-chain, ~3.5M sats fee
- **Files**: `last/src/script/plonk_with_poseidon/`
  - `global/`: Fiat-Shamir, coset vanishing, logup, line coefficients (62 scripts)
  - `per_query/`: Domain points, numerators, FRI folding (14 scripts × 8 queries)

## Key Technical Details

### Column Structure (PlonkWithPoseidon)
- Preprocessed: 50 (10 PLONK + 40 Poseidon)
- Trace: 60 (12 PLONK + 48 Poseidon)
- Interaction: 16 (8 PLONK + 8 Poseidon)
- Composition: 4
- **Total**: 130 columns

### Dual Log Sizes
- log_size 24: Preprocessed, trace, interaction columns
- log_size 27: Composition columns
- FRI folding: 27 → 16 (11 inner layers)

### LDM (Local Data Memory)
- State passing between Bitcoin scripts via hash commitments
- Global LDM: Shared state (alphas, line coefficients, etc.)
- Per-query LDM: Query-specific state (domain points, intermediate values)

## Data Files
- `hybrid_hash.bin`: Outer proof for delegation (80 KB)
- `bitcoin_proof.bin`: Inner proof for delegation (101 KB)
- `alternative1_proof.bin`: Direct PlonkWithoutPoseidon proof (99 KB)
- `poseidon_accelerated_proof.bin`: PlonkWithPoseidon proof (80 KB)

## Dependencies
- `stwo-prover`: Bitcoin-Wildlife-Sanctuary fork, `cp-poseidon-flattened` branch
- `recursive-stwo`: Rev `caea77f` (delegation approach uses default branch)
- `covenants-gadgets`: Tag 1.1.1
- `rand`: 0.9.3 (updated for security fix)

## Conclusion
**Delegation is the winner** due to:
1. Smallest on-chain footprint
2. Practical proof generation requirements
3. Proven to work end-to-end

The hybrid hasher is the key enabler - it allows efficient recursion while maintaining Bitcoin compatibility.

## Future Work
- The PlonkWithPoseidon direct verification is complete but ~3x more expensive
- Could be useful if delegation overhead becomes unacceptable
- Alternative 1 demonstrates single-proof is possible but compute-intensive
