# Alternative 1: Proof Requirements Analysis

## Current Proof Structure

The current two-tier delegation system uses:

### Outer Proof (hybrid_hash.bin) - PlonkWithPoseidon
- **log_size_plonk**: 15 (32,768 rows)
- **log_size_poseidon**: 15 (32,768 rows)
- **FRI inner layers**: 10
- **FRI last layer poly log_size**: 7
- **Hasher**: Sha256Poseidon31MerkleHasher (hybrid)
- **Total columns**: 126 (plonk + poseidon)

### Inner Proof (bitcoin_proof.bin) - PlonkWithoutPoseidon
- **log_size_plonk**: 17 (131,072 rows)
- **FRI inner layers**: 18
- **FRI last layer poly log_size**: 0
- **Hasher**: Sha256MerkleHasher (pure SHA256)
- **Total columns**: 28 (plonk only)
- **plonk_total_sum**: Non-zero (expects delegation inputs)

## Alternative 1 Proof Requirements

For Alternative 1 (Pure SHA256, no delegation), we need a **new proof** with:

### 1. Zero Total Sum
```
plonk_total_sum + input_sum == 0
```
Where `input_sum` only includes the minimal 3 application inputs:
- `(1, QM31::one())`
- `(2, QM31::from_u32_unchecked(0, 1, 0, 0))`
- `(3, QM31::from_u32_unchecked(0, 0, 1, 0))`

### 2. Proof Type: PlonkWithoutPoseidon<Sha256MerkleHasher>

The proof must use the `PlonkWithoutPoseidon` circuit with pure SHA256 Merkle hasher.

### 3. Expected Size Impact

Without the Poseidon accelerator, the computation being proved would need to be encoded differently. Options:

**Option A: Poseidon-via-Gates**
If the application uses Poseidon hashing, encode Poseidon operations as:
- pow5 gates (for S-box operations)
- m4 matrix multiplication gates
- arithmetic gates for round constants

This keeps `log_size_plonk` reasonable but increases constraint complexity.

**Option B: Pure computation without Poseidon**
If the application doesn't need Poseidon, use standard plonk gates only.
This may result in different `log_size_plonk` depending on the computation.

## Impact on Verifier Scripts

The verifier script structure depends on:

| Parameter | Current Inner | Alt 1 (estimated) | Impact |
|-----------|---------------|-------------------|--------|
| log_size_plonk | 17 | Varies | FRI layer count |
| FRI inner layers | 18 | Varies | Folding scripts |
| Total columns | 28 | 28 | No change |
| Queries | 8 | 8 | Per-query scripts |

### Key Variable: FRI Layers

FRI layer count depends on:
```
num_layers = log_size_plonk - log_blowup_factor - folding_factor - last_layer_log_size
```

Current config: `FriConfig::new(0, 9, 8)` = (log_last_layer, folding_factor, n_queries)

For log_size_plonk=17:
- With 9 folding levels and last_layer_log_size=0
- 18 inner layers makes sense

## Estimated Costs with Different Proof Sizes

| log_size_plonk | FRI layers | Scripts (est.) | Fee (est.) |
|----------------|------------|----------------|------------|
| 17 (current) | 18 | 131 | ~1.28M sats |
| 18 | 19 | ~143 | ~1.4M sats |
| 19 | 20 | ~155 | ~1.5M sats |
| 20 | 21 | ~167 | ~1.6M sats |

Each additional FRI layer adds folding scripts per query (8 queries × ~4 scripts = ~32 scripts per layer).

## Current Measurements (with existing bitcoin_proof.bin)

**WARNING**: These measurements use the current `bitcoin_proof.bin` which:
1. Has non-zero `plonk_total_sum` (expects delegation inputs)
2. Verification checks are DISABLED for measurement
3. Would FAIL with a proper Alternative 1 proof

Measured with disabled checks:
- **Scripts**: 131
- **Total fee**: 1,282,441 sats
- **Reduction vs current**: ~30%

## Next Steps to Get Accurate Measurements

1. **Generate Alternative 1 proof** using the prover with:
   - `prove_plonk_without_poseidon::<Sha256MerkleChannel>(...)`
   - Application circuit that produces `plonk_total_sum + input_sum == 0`

2. **Re-run verification** with the new proof to get actual:
   - FRI layer count
   - Script sizes
   - Total weight units

3. **Compare** with current delegation system

## Conclusion

The current measurement of ~1.28M sats is a **lower bound** estimate. The actual Alternative 1 cost depends on:
1. What computation is being proved
2. Whether Poseidon-via-gates is needed
3. The resulting `log_size_plonk`
4. FRI configuration

A proper Alternative 1 proof is required for accurate weight unit measurements.
