# PlonkWithPoseidon Bitcoin Verification Plan

## Goal

Generate a `PlonkWithPoseidonProof<Sha256MerkleHasher>` that verifies level13-1.bin, then build Bitcoin scripts to verify it. This gives us a real comparison between:

| Approach | Circuit Size | Proof Columns | Bitcoin Scripts | Prover Cost | Verifier Cost |
|----------|-------------|---------------|-----------------|-------------|---------------|
| PlonkWithoutPoseidon (alt1) | 2^21 rows | ~28 | ~131 | High (64GB+) | ~1.3M sats |
| **PlonkWithPoseidon (this)** | ~2^15 rows | ~130 | ~300 (est) | Lower | ~3M sats (est) |

---

## Phase 1: Proof Generator

### 1.1 Create poseidon_proof_generator crate

- [ ] Create `poseidon_proof_generator/Cargo.toml`
- [ ] Add to workspace in root `Cargo.toml`
- [ ] Set up dependencies (same as alt1_proof_generator plus PlonkWithPoseidon support)

### 1.2 Implement proof generation

The circuit verifies `level13-1.bin` (a `PlonkWithPoseidonProof<Poseidon31MerkleHasher>`) under a new `PlonkWithPoseidon` constraint system with `Sha256MerkleChannel` output.

- [ ] Load level13-1.bin proof
- [ ] Create constraint system with `ConstraintSystemRef::new_plonk_with_poseidon_ref()`
- [ ] Allocate proof variables with `PlonkWithPoseidonProofVar::new_witness()`
- [ ] Run Fiat-Shamir verification (inner Poseidon31 channel)
- [ ] Run composition check
- [ ] Run answer verification
- [ ] Run folding verification
- [ ] Call `cs.pad()`, `cs.check_arithmetics()`, `cs.populate_logup_arguments()`, `cs.check_poseidon_invocations()`
- [ ] Generate circuit with `cs.generate_plonk_with_poseidon_circuit()`
- [ ] Prove with `prove_plonk_with_poseidon::<Sha256MerkleChannel>()`
- [ ] Verify proof passes `verify_plonk_with_poseidon::<Sha256MerkleChannel>()`
- [ ] Save to `data/poseidon_accelerated_proof.bin`

### 1.3 Validation mode

- [ ] Add validation-only mode (skip actual proof generation)
- [ ] Print circuit statistics:
  - Number of PLONK rows
  - Number of Poseidon invocations
  - log_size_plonk and log_size_poseidon
- [ ] Estimate memory requirements

### 1.4 Test with small proof first

- [ ] Create a minimal test circuit (like alt1's 1*1=1)
- [ ] Verify end-to-end flow works before full level13 verification

**Exit criteria:** `poseidon_accelerated_proof.bin` generated and passes stwo verification.

---

## Phase 2: Bitcoin Script Infrastructure

### 2.1 Understand PlonkWithPoseidon proof structure

The proof has different structure from PlonkWithoutPoseidon:

```rust
// PlonkWithPoseidonProof structure
stmt0: {
    log_size_plonk: u32,      // e.g., 15
    log_size_poseidon: u32,   // e.g., 15 (can differ from plonk)
}
stmt1: {
    plonk_total_sum: QM31,
    poseidon_total_sum: QM31,
}
stark_proof: {
    commitments: [4 trees],
    sampled_values: [
        tree[0]: 50 preprocessed columns (10 plonk + 40 poseidon)
        tree[1]: 60 trace columns (12 plonk + 48 poseidon)
        tree[2]: 16 interaction columns (8 plonk + 8 poseidon)
        tree[3]: 4 composition columns
    ],
    fri_proof: { ... }
}
```

- [ ] Document exact column layout for PlonkWithPoseidon
- [ ] Map column indices to names (a_wire, b_wire, ..., in_state[0], ..., out_state[15])
- [ ] Understand which columns are at which log_size

### 2.2 Create column label generators

New file: `last/src/script/plonk_with_poseidon/labels.rs`

- [ ] `generate_plonk_preprocessed_labels()` - 10 columns
- [ ] `generate_plonk_trace_labels()` - 12 columns  
- [ ] `generate_plonk_interaction_labels()` - 8 columns
- [ ] `generate_poseidon_preprocessed_labels()` - 40 columns
- [ ] `generate_poseidon_trace_labels()` - 48 columns (in_state, intermediate_state, out_state)
- [ ] `generate_poseidon_interaction_labels()` - 8 columns
- [ ] `generate_composition_labels()` - 4 columns

### 2.3 Create hints infrastructure

New files in `last/src/script/hints/`:

- [ ] `plonk_with_poseidon_fiat_shamir.rs` - FiatShamirHints for PlonkWithPoseidon
- [ ] `plonk_with_poseidon_decommit.rs` - DecommitHints handling both PLONK and Poseidon columns
- [ ] `plonk_with_poseidon_answer.rs` - AnswerHints for combined columns
- [ ] `plonk_with_poseidon_folding.rs` - FoldingHints

**Exit criteria:** All hint structures compile and can be computed from proof.

---

## Phase 3: Global Bitcoin Scripts

### 3.1 Fiat-Shamir scripts

Modify/create scripts that handle PlonkWithPoseidon channel mixing:

- [ ] `pwp_part1_fiat_shamir.rs` - Mix commitment roots (4 trees, more columns)
- [ ] `pwp_part3_fiat_shamir.rs` - Handle two log_sizes, two total_sums

Key differences:
- Must mix `log_size_plonk` AND `log_size_poseidon`
- Must mix `plonk_total_sum` AND `poseidon_total_sum`
- More commitment data to process

### 3.2 Composition scripts

- [ ] `pwp_part4_composition.rs` - PLONK composition constraints
- [ ] `pwp_part5_composition.rs` - Poseidon composition constraints (NEW)
- [ ] `pwp_part6_composition.rs` - Combined constraint aggregation

### 3.3 Coset vanishing scripts

- [ ] `pwp_part7_coset_vanishing.rs` - Handle both log_sizes
- [ ] `pwp_part8_coset_vanishing.rs`
- [ ] `pwp_part9_coset_vanishing.rs`

### 3.4 Logup scripts

- [ ] `pwp_part10_logup.rs` - PLONK logup verification
- [ ] `pwp_part10b_logup.rs` - Poseidon logup verification (NEW)

### 3.5 Line coefficient scripts

This is the biggest expansion - need scripts for ~130 columns instead of ~28:

- [ ] `pwp_part11_point_shift.rs`
- [ ] `pwp_part12_line_coeffs.rs` - Shifted interaction columns (16 instead of 4)
- [ ] `pwp_part13_line_coeffs.rs` - Original columns at log_size_plonk (need ~60 scripts for 120 columns)
- [ ] `pwp_part13b_line_coeffs.rs` - Original columns at log_size_poseidon (if different)
- [ ] `pwp_part14_line_coeffs.rs` - Composition columns

**Estimated scripts:** 
- Current: 16 line coefficient scripts
- New: ~65-70 line coefficient scripts

**Exit criteria:** All global scripts compile and produce valid Bitcoin script.

---

## Phase 4: Per-Query Bitcoin Scripts

### 4.1 Domain point computation

- [ ] `pwp_part1_domain_point.rs` - Same as current, but handle dual log_sizes

### 4.2 Numerator scripts (PLONK columns)

- [ ] `pwp_part2_numerator.rs` - Preprocessed PLONK decommitment (10 cols)
- [ ] `pwp_part3_numerator.rs` - Trace PLONK decommitment (12 cols)
- [ ] `pwp_part4_numerator.rs` - Interaction PLONK numerator computation

### 4.3 Numerator scripts (Poseidon columns) - NEW

- [ ] `pwp_part5_numerator.rs` - Preprocessed Poseidon decommitment (40 cols)
- [ ] `pwp_part6_numerator.rs` - Trace Poseidon decommitment (48 cols) - may need multiple scripts
- [ ] `pwp_part7_numerator.rs` - Interaction Poseidon numerator computation

### 4.4 Combined numerator

- [ ] `pwp_part8_numerator.rs` - Aggregate all numerator contributions

### 4.5 FRI decommitment

- [ ] `pwp_part9_fri_decommitment.rs` - Handle both log_sizes in FRI layers

### 4.6 Folding scripts

- [ ] `pwp_part10_folding.rs` through `pwp_part13_folding.rs`
- [ ] `pwp_part14_clear.rs`

**Estimated per-query scripts:**
- Current: 13 scripts per query
- New: ~25-30 scripts per query

**Exit criteria:** All per-query scripts compile and produce valid Bitcoin script.

---

## Phase 5: Integration

### 5.1 Covenant integration

- [ ] Create `covenant_pwp/` or modify `covenant/` to support PlonkWithPoseidon
- [ ] Implement `push_pwp_information()` function
- [ ] Wire up all scripts in correct order
- [ ] Handle dual LDM state (plonk + poseidon)

### 5.2 Test harness

- [ ] Load `poseidon_accelerated_proof.bin`
- [ ] Verify proof with stwo first
- [ ] Generate all Bitcoin scripts
- [ ] Run simulation test

### 5.3 Measurement

- [ ] Count total scripts
- [ ] Measure total vbytes
- [ ] Calculate total fee at 1 sat/vbyte
- [ ] Compare with PlonkWithoutPoseidon numbers

**Exit criteria:** `test_covenant_pwp` passes, weight units measured.

---

## Phase 6: Optimization (Optional)

### 6.1 Script size optimization

- [ ] Identify largest scripts
- [ ] Look for redundant computations
- [ ] Consider batching strategies

### 6.2 Column batching

- [ ] Can we batch multiple Poseidon columns per script?
- [ ] Trade-off: script complexity vs count

---

## File Structure

```
recursive-stwo-bitcoin/
├── poseidon_proof_generator/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── last/
│   └── src/
│       └── script/
│           ├── plonk_with_poseidon/     # NEW
│           │   ├── mod.rs
│           │   ├── labels.rs
│           │   ├── global/
│           │   │   ├── mod.rs
│           │   │   ├── part1_fiat_shamir.rs
│           │   │   ├── ...
│           │   └── per_query/
│           │       ├── mod.rs
│           │       ├── part1_domain_point.rs
│           │       ├── ...
│           └── hints/
│               ├── plonk_with_poseidon_fiat_shamir.rs  # NEW
│               ├── plonk_with_poseidon_decommit.rs     # NEW
│               └── ...
├── covenant/
│   └── src/
│       ├── lib.rs           # Add PlonkWithPoseidon support
│       └── plonk_with_poseidon.rs  # NEW
└── data/
    └── poseidon_accelerated_proof.bin  # Generated proof
```

---

## Dependencies & Risks

### Dependencies
1. Phase 2-5 depend on Phase 1 (need proof file)
2. Phase 4 depends on Phase 3 (global scripts set up LDM state)
3. Phase 5 depends on Phase 3+4

### Risks
1. **Proof generation memory** - PlonkWithPoseidon should be much smaller than PlonkWithoutPoseidon, but still need to verify
2. **Dual log_size handling** - If log_size_plonk != log_size_poseidon, FRI verification becomes more complex
3. **Script size limits** - Individual scripts must fit in Bitcoin's limits (~4MB)
4. **Poseidon constraint verification** - Need to understand Poseidon accelerator constraints for Bitcoin script

### Mitigations
- Start with validation mode to measure circuit size
- Test with same log_size for plonk and poseidon first
- Monitor individual script sizes during development

---

## Estimated Timeline

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Proof Generator | 3-4 days | None |
| Phase 2: Infrastructure | 2-3 days | Phase 1 (for testing) |
| Phase 3: Global Scripts | 4-5 days | Phase 2 |
| Phase 4: Per-Query Scripts | 5-6 days | Phase 2, 3 |
| Phase 5: Integration | 3-4 days | Phase 3, 4 |
| Phase 6: Optimization | 2-3 days | Phase 5 |
| **Total** | **~3-4 weeks** | |

---

## Success Metrics

1. **Proof generation succeeds** with reasonable resources (<32GB RAM)
2. **All Bitcoin scripts pass** simulation test
3. **Measured weight units** documented
4. **Comparison table** completed with real numbers

---

## Current Status

- [x] Plan created
- [x] Phase 1: Proof Generator (COMPLETE - 2024-04-14)
  - Proof generated: `data/poseidon_accelerated_proof.bin` (80,400 bytes)
  - Generation time: 93.64s
  - Circuit: PLONK 2^15 + Poseidon 2^15 rows (64x smaller than alt1)
  - Sampled values: 138 total (50 preprocessed + 60 trace + 24 interaction + 4 composition)
- [x] Phase 2: Infrastructure (COMPLETE - 2026-04-14)
  - [x] Created labels module: `last/src/script/plonk_with_poseidon/labels.rs`
  - [x] Verified column structure matches proof (50+60+16+4 = 130 columns)
  - [x] Stack usage analysis: safe (can process 32 cols/script, using 2)
  - [x] Script count estimate: ~220 total (1.7x increase from 131)
  - [x] Created hints module: `last/src/script/plonk_with_poseidon/hints.rs`
  - [x] PwpFiatShamirHints successfully loads proof and extracts all data
  - [ ] Create remaining hint types (Answer, Decommit, Folding)
- [x] Phase 3: Global Scripts (COMPLETE - 2026-04-14)
  - [x] Created Fiat-Shamir scripts (6 parts):
    - part1_fiat_shamir: 691 bytes (commitments, z/alpha)
    - part2_fiat_shamir: 718 bytes (total_sums, oods_t)
    - part3_fiat_shamir: 2,883 bytes (50 preprocessed columns)
    - part4_fiat_shamir: 5,175 bytes (60 trace columns)
    - part5_fiat_shamir: 2,385 bytes (16 interaction + 4 composition)
    - part6_fiat_shamir: 12,195 bytes (128 last_layer_coeffs + FRI + PoW + queries)
    - **Total Fiat-Shamir: 24,047 bytes**
  - [x] Created coset vanishing scripts (3 parts):
    - part7_coset_vanishing: 49,907 bytes (oods_point + first 2 doublings)
    - part8_coset_vanishing: 52,997 bytes (doublings 3-10)
    - part9_coset_vanishing: 40,186 bytes (doublings 11-15 + inverse)
    - **Total Coset Vanishing: 143,090 bytes**
  - [x] Created logup script:
    - part10_logup: 47,050 bytes (PLONK wire lookup relation)
  - [x] Created point shift script:
    - part11_point_shift: 28,892 bytes (logup verification + randomizer init)
  - [x] Created line coefficient scripts (69 total):
    - Shifted interaction (4 scripts): 183,488 bytes (8 columns)
    - Original log_size 24 (63 scripts): 2,889,936 bytes (126 columns)
    - Composition log_size 27 (2 scripts): 91,744 bytes (4 columns)
    - **Total Line Coeffs: 3,165,168 bytes**
  - [ ] Create composition constraint scripts (PLONK + Poseidon verification) - OPTIONAL
  
  **Global Scripts Summary (80 scripts):**
  - Total size: 3,408,247 bytes (3.3 MB)
  - Average script size: 42,603 bytes
  - Script count increase vs alt1: 3.0x (80 vs ~27)
- [x] Phase 4: Per-Query Scripts (IN PROGRESS - 2026-04-14)
  - [x] Created hints infrastructure:
    - PwpFiatShamirHints: Fiat-Shamir transcript and challenges
    - PwpDecommitHints: Merkle proof decommitments for all 4 trees
    - PwpAnswerHints: FRI answers at query positions
  - [x] Fixed sample_points structure for preprocessed columns (50 columns)
  - [ ] Create folding hints (complex FRI layer structure)
  - [ ] Create per-query scripts:
    - Domain point computation (needs new precomputed tree for log_sizes 24/27)
    - Numerator scripts for 130 columns
    - FRI decommitment
    - FRI folding (10 inner layers)
  
  **Hints Infrastructure Working:**
  - All log_sizes correct: {24, 27}
  - Trees: 50 preprocessed + 60 trace + 16 interaction + 4 composition = 130 columns
  - 8 FRI queries configured
  
  **Blocking Issues:**
  - Precomputed tree built for alt1 (log_sizes 26/28), needs new tree for 24/27
  - Alternatively, compute domain points directly (larger scripts)
- [ ] Phase 5: Integration
- [ ] Phase 6: Optimization
