# Alternative 1 Implementation Plan

## Goal

Produce a Bitcoin-verifiable proof that directly verifies the recursion chain output (`level13-1.bin`) using **only SHA256** — no Poseidon accelerator, no hybrid intermediate step.

```
level13-1.bin (PlonkWithPoseidonProof<Poseidon31MerkleHasher>, UNCHANGED)
    │
    │  [NEW: single verification circuit in PlonkWithoutPoseidon]
    ▼
alt1_proof.bin = PlonkWithoutPoseidonProof<Sha256MerkleHasher>
    │
    │  [existing covenant/ and last/ verifier — minor adjustments]
    ▼
Bitcoin scripts verify
```

**No `alt1_hybrid.bin`.** Single proof, single generation step.

---

## Circuit Architecture

The new verification circuit is built under `ConstraintSystemRef::new_plonk_without_poseidon_ref()` and contains:

| Responsibility | Mechanism |
|----------------|-----------|
| Verify `level13-1.bin` Poseidon31 Merkle paths | Emulated Poseidon via `pow5` / `m4` / `hadamard` / `arith` gates (no accelerator sub-circuit) |
| Simulate inner `Poseidon31MerkleChannel` Fiat-Shamir | Existing `ChannelVar` (Poseidon31-based) — runs via emulation under PlonkWithoutPoseidon |
| Outer Fiat-Shamir for this new proof | **NEW: `Sha256ChannelVar`** — iterative SHA256 in arithmetic gates |
| Compose constraint checks, answer/folding | Existing `recursive/` components (composition, answer, folding) |
| Prove the circuit | `prove_plonk_without_poseidon::<Sha256MerkleChannel>` |

**Trade-off:** Each Poseidon invocation in the circuit costs many gates (vs. 1 accelerator call), so circuit size grows. But no hybrid layer, no Poseidon sub-circuit, pure SHA256 output.

---

## Existing Infrastructure Audit

Investigation of `~/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/` and local `primitives/`:

### Reusable (no changes)

| Component | Location | Notes |
|-----------|----------|-------|
| `Poseidon2HalfVar` (Native + Emulated dispatch) | `primitives/poseidon31/src/lib.rs` | Auto-dispatches based on CS type. Emulated path implements all 30 Poseidon2 rounds using `pow5`, `do_m4_gate`, `do_pow5m4_gate`. Works under `PlonkWithoutPoseidon` transparently. |
| `Poseidon31MerkleHasherVar` | `primitives/merkle/` | Built on `Poseidon2HalfVar` — emulation works through. |
| `ChannelVar` (Poseidon31 sponge) | `primitives/channel/src/lib.rs` | Inner channel for replaying level13's Fiat-Shamir. Emulated under PlonkWithoutPoseidon. |
| `recursive/` components (`fiat_shamir`, `answer`, `composition`, `folding`) | `components/recursive/` | Currently target `PlonkWithPoseidonProof<Poseidon31MerkleHasher>`. Inner logic reusable; CS target must switch to PlonkWithoutPoseidon. |
| `prove_plonk_without_poseidon::<Sha256MerkleChannel>` | stwo-prover | Entry point for the final prove. |

### Missing — Must Be Built

| Gap | Description | Effort |
|-----|-------------|--------|
| **`Sha256ChannelVar`** | No DSL Fiat-Shamir gadget for SHA256 exists. The local `primitives/src/channel/sha256.rs` is a Bitcoin Script gadget (`BitcoinSystemRef`), **not** a circuit-level (`ConstraintSystemRef`) gadget. Must implement SHA256 compression function using arithmetic gates (bit decompositions + round functions) or a lookup-based approach. | **Large (1–2 weeks)** |
| Integration wiring | `recursive/` components hardcode `new_plonk_with_poseidon_ref()` in their test harnesses and use Poseidon31 inner channel throughout. Need glue that splits: inner channel (Poseidon31, for replaying level13 FS) vs. outer channel (new SHA256ChannelVar, for this proof's FS). | Medium (3–5 days) |
| End-to-end driver | New binary analogous to `last-layer/main.rs` but targeting `PlonkWithPoseidonProof<Poseidon31MerkleHasher>` (level13) → `PlonkWithoutPoseidonProof<Sha256MerkleHasher>` (alt1). | Small (1–2 days) |
| `last/` (covenant) adjustments | Currently verifies `alternative1_proof.bin` with trivial structure. Needs to verify the new alt1 proof structure. Mostly mechanical. | Small (1–2 days) |

---

## Critical Path: `Sha256ChannelVar`

This is the one substantial new gadget. It must expose the same interface as `stwo::core::channel::Sha256Channel`:

```rust
trait ChannelVar {
    fn mix_root(&mut self, root: &Sha256HashVar);        // 32-byte commitment
    fn mix_felts(&mut self, felts: &[QM31Var]);           // iterative per-felt SHA256
    fn mix_u64(&mut self, n: u64);
    fn mix_u32s(&mut self, words: &[u32]);
    fn draw_felt(&mut self) -> QM31Var;
    fn draw_felts<const N: usize>(&mut self) -> [QM31Var; N];
}
```

### Implementation options

1. **Bitwise SHA256 in arithmetic gates**
   - Decompose each 32-bit word into bits, run SHA256 compression function (64 rounds of Ch, Maj, rotations, additions) purely in arithmetic gates.
   - Pros: straightforward, no new primitives needed.
   - Cons: very large constraint count per SHA256 invocation.

2. **Lookup-based SHA256**
   - Use byte-table lookups for S-box-like operations and 8-bit limb arithmetic for additions.
   - Pros: much smaller gate count.
   - Cons: requires adding lookup infrastructure to PlonkWithoutPoseidon (may already be partly available via `lookup_elements`).

3. **Chunked SHA256 via pow5 gates**
   - SHA256 has no natural alignment with `pow5`/`m4`, so this likely doesn't help.

**Recommendation:** Start with option 1 (bitwise) to unblock integration, then optimize to option 2 if circuit size is prohibitive.

---

## Staged Implementation Plan

### Phase 1 — Feasibility & Scaffolding (3–5 days)

1. Create `alt1_proof_generator/` crate skeleton (analogous to existing `proof_generator/`).
2. Wire up loading of `level13-1.bin` and `FiatShamirHints<Poseidon31MerkleChannel>`.
3. Verify that `recursive/` components can be invoked under `new_plonk_without_poseidon_ref()` by running an existing test with the CS type swapped. Measure gate count impact of emulated Poseidon.
4. Write a stub `Sha256ChannelVar` that panics on every call — wire it into the outer Fiat-Shamir points. Confirm the circuit compiles end-to-end with stubs.

**Exit criteria:** A buildable circuit that loads level13, allocates all proof variables, and reaches the outer Fiat-Shamir calls (which panic). Gate count for emulated Poseidon is measured.

### Phase 2 — `Sha256ChannelVar` Gadget (1–2 weeks)

1. Implement bitwise SHA256 compression in arithmetic gates. Unit-test against `stwo::core::channel::Sha256Channel`.
2. Implement `mix_root`, `mix_felts` (iterative), `mix_u64`, `mix_u32s`, `draw_felt[s]` matching the stwo Sha256Channel semantics exactly.
3. Add DSL-level tests: allocate a channel, run a scripted sequence of mixes/draws, assert the resulting felts match the native implementation.

**Exit criteria:** `Sha256ChannelVar` passes parity tests against `stwo::core::channel::Sha256Channel`.

### Phase 3 — Integration (3–5 days)

1. Replace `Sha256ChannelVar` stubs with the real implementation.
2. Run full `alt1_proof_generator`: generate circuit, prove with `prove_plonk_without_poseidon::<Sha256MerkleChannel>`, verify with `verify_plonk_without_poseidon::<Sha256MerkleChannel>`.
3. Inspect proof structure — confirm FRI inner layer count, log sizes, etc., match what `last/` covenant expects.

**Exit criteria:** Valid `alt1_proof.bin` that passes stwo verification.

### Phase 4 — Covenant Verification (2–3 days)

1. Update `covenant/src/lib.rs` to load the new `alt1_proof.bin`.
2. Adjust `last/` scripts if proof structure differs from current expectations (log sizes, number of FRI layers, sampled_values layout).
3. Run covenant test. Measure weight and fee.

**Exit criteria:** `cargo test -p recursive-stwo-covenant test_covenant` passes on the real alt1 proof.

---

## Open Questions / Risks

1. **Circuit size blowup.** Emulated Poseidon + bitwise SHA256 may produce a circuit large enough that proving time becomes impractical (hours+) or FRI parameters don't fit the current `PcsConfig`. Need to measure early in Phase 1.
2. **Lookup infrastructure.** If option 2 (lookup-based SHA256) is needed, we may need to extend `PlonkWithoutPoseidon` with lookup support — this is a larger change.
3. **`last/` proof structure compatibility.** The current `last/` scripts are coded against specific `sampled_values` layout, log sizes, FRI layer counts. The new alt1 proof will have different characteristics. Some hardcoded asserts (`fri_proof.inner_layers.len() == 18`, etc.) will need adjustment.
4. **Channel parity subtleties.** `Sha256Channel::mix_felts` serializes each QM31 as 4 M31s little-endian with specific padding. Getting the exact byte-level behavior right in-circuit is easy to miss and hard to debug.
5. **Existing `alternative1_proof.bin`** (the trivial `1*1=1` proof) will be replaced. Keep it around as a smoke-test artifact.

---

## Estimated Total Effort

**3–4 weeks of focused work**, dominated by `Sha256ChannelVar` (Phase 2).

Phase 1 should be completed first and its outputs (gate count measurements, compile-through) used to validate/revise the plan before committing to Phase 2.

---

## Progress Update (2024-04-14)

### Phase 1 COMPLETE: Circuit Validation

**Result: SUCCESS** - The verification circuit passes all validation checks.

```
cargo run --release -p alt1-proof-generator

Mode: LEVEL13 (full)
After proof allocation: 307 rows
After Fiat-Shamir: 69,138 rows
After Composition: 71,195 rows  
After Answer: 479,056 rows
After Folding: 1,369,882 rows

check_arithmetics PASSED!
populate_logup_arguments PASSED!

Final circuit log_size: 21 (2,097,152 rows)
```

### Key Findings

1. **No `Sha256ChannelVar` needed** - The outer SHA256 Fiat-Shamir runs natively in `prove_plonk_without_poseidon::<Sha256MerkleChannel>`, not in-circuit.

2. **Emulated Poseidon works** - The existing `Poseidon2HalfVar::Emulated` automatically handles Poseidon operations under `PlonkWithoutPoseidon` constraint system.

3. **Circuit size challenge** - The verification circuit is 2^21 rows. With blowup factor 7:
   - Evaluation domain: 2^28 = 268M elements
   - Memory requirement: ~50+ GB
   - Makes proof generation impractical on typical machines

### Next Steps

**Option A: High-memory proof generation**
- Run on a machine with 64+ GB RAM
- Use smaller blowup factor (e.g., 5) to reduce memory at cost of larger proof

**Option B: Circuit optimization**
- The main costs are Answer (408K rows) and Folding (891K rows)
- These involve Merkle decommitment verification with many Poseidon invocations
- Could potentially optimize by batching or reducing query count

**Option C: Accept validation as milestone**
- Circuit correctness is proven
- Document the approach for future implementation when resources allow
