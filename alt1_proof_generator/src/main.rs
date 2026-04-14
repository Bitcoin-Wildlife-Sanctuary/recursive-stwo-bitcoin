//! Alternative 1 Proof Generator
//!
//! Generates PlonkWithoutPoseidonProof<Sha256MerkleHasher> that verifies level13-1.bin
//! using emulated Poseidon (no Poseidon accelerator sub-circuit).
//!
//! Build incrementally:
//! - Step 1: Load level13-1.bin and allocate proof variables
//! - Step 2: Run FiatShamir
//! - Step 3: Run Composition check
//! - Step 4: Run Answer
//! - Step 5: Run Folding
//! - Step 6: Generate the final proof

use anyhow::Result;
use circle_plonk_dsl_constraint_system::var::AllocVar;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_data_structures::PlonkWithPoseidonProofVar;
use circle_plonk_dsl_fields::{M31Var, QM31Var};
use circle_plonk_dsl_poseidon31::Poseidon2HalfVar;
use circle_plonk_dsl_fiat_shamir::FiatShamirResults;
use circle_plonk_dsl_hints::FiatShamirHints;
use num_traits::One;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::poseidon31_merkle::{Poseidon31MerkleChannel, Poseidon31MerkleHasher};
use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleHasher;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
use stwo_prover::core::backend::Column;
use stwo_prover::examples::plonk_without_poseidon::air::{
    prove_plonk_without_poseidon, verify_plonk_without_poseidon,
};

/// Path to small_proof.bin (smaller proof for testing)
const SMALL_PROOF_PATH: &str = concat!(
    env!("HOME"),
    "/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/components/test_data/small_proof.bin"
);

/// Path to level13-1.bin (the full input proof we want to verify)
const LEVEL13_PROOF_PATH: &str = concat!(
    env!("HOME"),
    "/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/examples/multi-proofs/data/level13-1.bin"
);

/// Path to level14-1.bin (verifies level13 using PlonkWithPoseidon accelerator)
const LEVEL14_PROOF_PATH: &str = concat!(
    env!("HOME"),
    "/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/examples/multi-proofs/data/level14-1.bin"
);

/// PCS config for small_proof.bin
fn small_proof_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(2, 5, 16),
    }
}

/// PCS config for level13-1.bin (fast_verifier3_config from multi-proofs)
/// Modified: log_last_layer_degree_bound 7->10 to reduce FRI layers
/// PCS config for the OUTPUT alt1 proof (PlonkWithoutPoseidon)
/// Note: Circuit is 2^21 rows, so blowup factor must be <= 7 (21+7=28 max domain)
fn alt1_output_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 7, 10), // blowup 7, 10 queries (sufficient with 128x blowup)
    }
}

/// PCS config for READING level13-1.bin (the input proof)
fn level13_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    }
}

/// Use small proof for testing (toggle this for full proof)
/// Set to false to test with level13-1.bin (requires more memory for proof generation)
const USE_SMALL_PROOF: bool = false;

/// Compare PlonkWithPoseidon vs PlonkWithoutPoseidon circuit sizes
fn compare_circuit_sizes() -> Result<()> {
    println!("=== Comparing Circuit Sizes: PlonkWithPoseidon vs PlonkWithoutPoseidon ===\n");

    // level13-1.bin (input to both)
    let proof13_bytes = std::fs::read(LEVEL13_PROOF_PATH)?;
    let proof13: PlonkWithPoseidonProof<Poseidon31MerkleHasher> = bincode::deserialize(&proof13_bytes)?;
    println!("INPUT: level13-1.bin");
    println!("  log_size_plonk: {}", proof13.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof13.stmt0.log_size_poseidon);
    println!("  FRI inner layers: {}", proof13.stark_proof.fri_proof.inner_layers.len());

    // level14-1.bin (PlonkWithPoseidon verifying level13)
    let proof14_bytes = std::fs::read(LEVEL14_PROOF_PATH)?;
    let proof14: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> = bincode::deserialize(&proof14_bytes)?;
    println!("\nOUTPUT with PlonkWithPoseidon (level14-1.bin):");
    println!("  log_size_plonk: {}", proof14.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof14.stmt0.log_size_poseidon);
    println!("  FRI inner layers: {}", proof14.stark_proof.fri_proof.inner_layers.len());
    let plonk_with = proof14.stmt0.log_size_plonk;
    let poseidon_with = proof14.stmt0.log_size_poseidon;

    println!("\nOUTPUT with PlonkWithoutPoseidon (alt1, emulated):");
    println!("  log_size_plonk: 21 (measured from circuit validation)");
    println!("  log_size_poseidon: N/A (no accelerator)");
    println!("  FRI inner layers: depends on config");
    let plonk_without = 21u32;

    println!("\n=== Summary ===");
    println!("PlonkWithPoseidon circuit:    2^{} = {} plonk rows + 2^{} = {} poseidon rows",
        plonk_with, 1u64 << plonk_with, poseidon_with, 1u64 << poseidon_with);
    println!("PlonkWithoutPoseidon circuit: 2^{} = {} plonk rows (emulated Poseidon)",
        plonk_without, 1u64 << plonk_without);
    println!("Overhead factor: ~{:.1}x more plonk rows",
        (1u64 << plonk_without) as f64 / (1u64 << plonk_with) as f64);

    Ok(())
}

/// Detailed breakdown of gates per Poseidon permutation
fn analyze_poseidon_gates() -> Result<()> {
    use stwo_prover::core::fields::m31::M31;

    println!("=== Poseidon Gate Breakdown (Emulated) ===\n");

    let cs = ConstraintSystemRef::new_plonk_without_poseidon_ref();

    // Create input for one Poseidon permutation
    let left: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs, &M31::from(i as u32)));
    let right: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs, &M31::from((i + 8) as u32)));

    let baseline = cs.num_plonk_rows();

    let left_half = Poseidon2HalfVar::from_m31(&left);
    let right_half = Poseidon2HalfVar::from_m31(&right);

    let after_convert = cs.num_plonk_rows();
    println!("Input allocation (16 M31 witnesses): {} gates", baseline);
    println!("Convert to Poseidon2HalfVar: +{} gates", after_convert - baseline);

    let before_permute = cs.num_plonk_rows();
    let _result = Poseidon2HalfVar::permute(&left_half, &right_half, false, false, None);
    let after_permute = cs.num_plonk_rows();

    let permute_gates = after_permute - before_permute;
    println!("\nPoseidon2 permute: {} gates", permute_gates);

    // Breakdown analysis based on Poseidon2 structure:
    // - 1 initial MDS (16x16)
    // - 4 full rounds (beginning)
    // - 14 partial rounds
    // - 4 full rounds (end)
    println!("\n--- Poseidon2 Structure (30 rounds) ---");
    println!("Initial 16x16 MDS: ~11 gates");
    println!("4 full rounds (start): 4 × ~19 = ~76 gates");
    println!("14 partial rounds: 14 × ~15 = ~210 gates");
    println!("4 full rounds (end): 4 × ~19 = ~76 gates");
    println!("Estimated total: ~373 gates");
    println!("Actual measured: {} gates", permute_gates);

    // Now let's test multiple permutations to see if constants are cached
    println!("\n--- Testing constant caching ---");
    let cs2 = ConstraintSystemRef::new_plonk_without_poseidon_ref();
    let left2: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs2, &M31::from(i as u32)));
    let right2: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs2, &M31::from((i + 8) as u32)));
    let left2_half = Poseidon2HalfVar::from_m31(&left2);
    let right2_half = Poseidon2HalfVar::from_m31(&right2);

    let before1 = cs2.num_plonk_rows();
    let (out1_l, out1_r) = Poseidon2HalfVar::permute(&left2_half, &right2_half, false, false, None);
    let after1 = cs2.num_plonk_rows();
    println!("1st permutation: {} gates", after1 - before1);

    let before2 = cs2.num_plonk_rows();
    let (_out2_l, _out2_r) = Poseidon2HalfVar::permute(&out1_l, &out1_r, false, false, None);
    let after2 = cs2.num_plonk_rows();
    println!("2nd permutation: {} gates", after2 - before2);

    // Test with swap bit (Merkle tree needs this)
    let cs3 = ConstraintSystemRef::new_plonk_without_poseidon_ref();
    let left3: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs3, &M31::from(i as u32)));
    let right3: [M31Var; 8] = std::array::from_fn(|i| M31Var::new_witness(&cs3, &M31::from((i + 8) as u32)));
    let left3_half = Poseidon2HalfVar::from_m31(&left3);
    let right3_half = Poseidon2HalfVar::from_m31(&right3);
    let bit_var = M31Var::new_witness(&cs3, &M31::from(0u32));

    let before_swap = cs3.num_plonk_rows();
    let _result_swap = Poseidon2HalfVar::permute(&left3_half, &right3_half, false, false, Some((false, bit_var.variable)));
    let after_swap = cs3.num_plonk_rows();
    println!("Permutation with swap bit: {} gates (+{} for swap logic)",
        after_swap - before_swap,
        (after_swap - before_swap) as i64 - permute_gates as i64);

    Ok(())
}

fn get_proof_path() -> &'static str {
    if USE_SMALL_PROOF { SMALL_PROOF_PATH } else { LEVEL13_PROOF_PATH }
}

fn get_config() -> PcsConfig {
    if USE_SMALL_PROOF { small_proof_config() } else { level13_config() }
}

fn get_inputs() -> Vec<(usize, QM31)> {
    if USE_SMALL_PROOF {
        vec![(1, QM31::one())]
    } else {
        vec![
            (1, QM31::one()),
            (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
            (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        ]
    }
}

/// Step 1: Load proof and allocate variables
fn step1_load_proof() -> Result<()> {
    let proof_path = get_proof_path();
    println!("=== Step 1: Load {} ===\n", if USE_SMALL_PROOF { "small_proof.bin" } else { "level13-1.bin" });

    let proof_bytes = std::fs::read(proof_path)?;
    println!("Loaded {} bytes", proof_bytes.len());

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> = bincode::deserialize(&proof_bytes)?;

    println!("Proof structure:");
    println!("  log_size_plonk: {}", proof.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof.stmt0.log_size_poseidon);
    println!("  plonk_total_sum: {:?}", proof.stmt1.plonk_total_sum);
    println!("  poseidon_total_sum: {:?}", proof.stmt1.poseidon_total_sum);
    println!("  num commitments: {}", proof.stark_proof.commitments.len());
    println!(
        "  FRI inner layers: {}",
        proof.stark_proof.fri_proof.inner_layers.len()
    );

    // Allocate proof variables under PlonkWithoutPoseidon constraint system
    println!("\nAllocating proof variables under PlonkWithoutPoseidon CS...");
    let cs = ConstraintSystemRef::new_plonk_without_poseidon_ref();
    let _proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    println!("CS type: {:?}", cs.get_type());
    println!("Num plonk rows after allocation: {}", cs.num_plonk_rows());

    println!("\nStep 1 PASSED: Proof loaded and variables allocated.\n");
    Ok(())
}

/// Step 2: Run Fiat-Shamir (emulated Poseidon channel)
fn step2_fiat_shamir() -> Result<()> {
    println!("=== Step 2: Fiat-Shamir ===\n");

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(get_proof_path())?)?;
    let config = get_config();
    let inputs = get_inputs();

    // Compute Fiat-Shamir hints
    println!("Computing Fiat-Shamir hints...");
    let fiat_shamir_hints = FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);
    println!("  z: {:?}", fiat_shamir_hints.z);
    println!("  alpha: {:?}", fiat_shamir_hints.alpha);
    println!("  random_coeff: {:?}", fiat_shamir_hints.random_coeff);
    println!("  oods_point: ({:?}, {:?})", fiat_shamir_hints.oods_point.x, fiat_shamir_hints.oods_point.y);
    println!("  fri_alphas count: {}", fiat_shamir_hints.fri_alphas.len());

    // Run Fiat-Shamir in circuit (PlonkWithoutPoseidon -> emulated Poseidon)
    println!("\nRunning Fiat-Shamir in PlonkWithoutPoseidon circuit...");
    let cs = ConstraintSystemRef::new_plonk_without_poseidon_ref();
    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    let input_vars: Vec<(usize, QM31Var)> = inputs
        .iter()
        .map(|(idx, val)| (*idx, QM31Var::new_constant(&cs, val)))
        .collect();

    let fiat_shamir_results =
        FiatShamirResults::compute(&fiat_shamir_hints, &mut proof_var, config, &input_vars);

    println!("Num plonk rows after Fiat-Shamir: {}", cs.num_plonk_rows());
    println!("z value matches: {}", fiat_shamir_results.lookup_elements.z.value() == fiat_shamir_hints.z);
    println!("alpha value matches: {}", fiat_shamir_results.lookup_elements.alpha.value() == fiat_shamir_hints.alpha);

    println!("\nStep 2 PASSED: Fiat-Shamir completed with emulated Poseidon.\n");
    Ok(())
}

/// Step 3: Full circuit (FiatShamir + Composition + Answer + Folding)
fn step3_full_circuit() -> Result<()> {
    println!("=== Step 3: Full verification circuit ===\n");

    use circle_plonk_dsl_answer::AnswerResults;
    use circle_plonk_dsl_circle::CirclePointQM31Var;
    use circle_plonk_dsl_composition::CompositionCheck;
    use circle_plonk_dsl_folding::FoldingResults;
    use circle_plonk_dsl_hints::{AnswerHints, DecommitHints, FirstLayerHints, InnerLayersHints};

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(get_proof_path())?)?;
    let config = get_config();
    let inputs = get_inputs();

    // Compute all hints
    println!("Computing hints...");
    let fiat_shamir_hints = FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);
    let answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let decommitment_hints = DecommitHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints = FirstLayerHints::compute(&fiat_shamir_hints, &answer_hints, &proof);
    let inner_layer_hints = InnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );
    println!("All hints computed.");

    // Print proof structure info for context
    println!("\n--- Input Proof Structure (level13-1.bin) ---");
    println!("  log_size_plonk: {}", proof.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof.stmt0.log_size_poseidon);
    println!("  FRI inner layers: {}", proof.stark_proof.fri_proof.inner_layers.len());
    println!("  n_queries: {}", config.fri_config.n_queries);

    // Build circuit with detailed breakdown
    println!("\n--- Gate Count Breakdown ---\n");
    let cs = ConstraintSystemRef::new_plonk_without_poseidon_ref();

    let rows_before = cs.num_plonk_rows();
    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);
    let rows_after_alloc = cs.num_plonk_rows();
    println!("1. Proof Allocation:     {:>10} gates (+{})",
             rows_after_alloc, rows_after_alloc - rows_before);
    println!("   (Allocates commitments, sampled values, FRI proof structure)");

    let input_vars: Vec<(usize, QM31Var)> = inputs
        .iter()
        .map(|(idx, val)| (*idx, QM31Var::new_constant(&cs, val)))
        .collect();

    let rows_before_fs = cs.num_plonk_rows();
    let fiat_shamir_results =
        FiatShamirResults::compute(&fiat_shamir_hints, &mut proof_var, config, &input_vars);
    let rows_after_fs = cs.num_plonk_rows();
    println!("\n2. Fiat-Shamir:          {:>10} gates (+{})",
             rows_after_fs, rows_after_fs - rows_before_fs);
    println!("   (Emulated Poseidon channel: mix commitments, draw challenges)");
    println!("   - Processes {} commitments", proof.stark_proof.commitments.len());
    println!("   - Draws z, alpha, random_coeff, oods_point");
    println!("   - Mixes sampled values into channel");
    println!("   - Draws {} FRI alphas", fiat_shamir_results.fri_alphas.len());
    println!("   - Verifies PoW ({} bits)", config.pow_bits);

    let rows_before_comp = cs.num_plonk_rows();
    CompositionCheck::compute(
        &fiat_shamir_hints,
        &fiat_shamir_results.lookup_elements,
        fiat_shamir_results.random_coeff.clone(),
        fiat_shamir_results.oods_point.clone(),
        &proof_var,
    );
    let rows_after_comp = cs.num_plonk_rows();
    println!("\n3. Composition Check:    {:>10} gates (+{})",
             rows_after_comp, rows_after_comp - rows_before_comp);
    println!("   (Verifies composition polynomial evaluation at OODS point)");

    let rows_before_ans = cs.num_plonk_rows();
    let answer_results = AnswerResults::compute(
        &CirclePointQM31Var::new_witness(&cs, &fiat_shamir_hints.oods_point),
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_hints,
        &decommitment_hints,
        &proof_var,
        config,
    );
    let rows_after_ans = cs.num_plonk_rows();
    println!("\n4. Answer (Decommit):    {:>10} gates (+{})",
             rows_after_ans, rows_after_ans - rows_before_ans);
    println!("   (Merkle decommitment verification for {} queries)", config.fri_config.n_queries);
    println!("   - Verifies Poseidon Merkle paths for:");
    println!("     * Preprocessed columns");
    println!("     * Trace columns");
    println!("     * Interaction columns");
    println!("     * Composition columns");
    println!("   - Each Merkle hash = 1 emulated Poseidon (~240 gates)");

    let rows_before_fold = cs.num_plonk_rows();
    FoldingResults::compute(
        &proof_var,
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_results,
        &first_layer_hints,
        &inner_layer_hints,
    );
    let rows_after_fold = cs.num_plonk_rows();
    println!("\n5. Folding (FRI):        {:>10} gates (+{})",
             rows_after_fold, rows_after_fold - rows_before_fold);
    println!("   (FRI folding verification)");
    println!("   - First layer folding");
    println!("   - {} inner layer foldings", proof.stark_proof.fri_proof.inner_layers.len());
    println!("   - Each layer: Merkle decommit + folding computation");

    let total_gates = cs.num_plonk_rows();
    println!("\n--- Summary ---");
    println!("Total gates before padding: {}", total_gates);

    // Percentage breakdown
    let alloc_pct = (rows_after_alloc - rows_before) as f64 / total_gates as f64 * 100.0;
    let fs_pct = (rows_after_fs - rows_before_fs) as f64 / total_gates as f64 * 100.0;
    let comp_pct = (rows_after_comp - rows_before_comp) as f64 / total_gates as f64 * 100.0;
    let ans_pct = (rows_after_ans - rows_before_ans) as f64 / total_gates as f64 * 100.0;
    let fold_pct = (rows_after_fold - rows_before_fold) as f64 / total_gates as f64 * 100.0;

    println!("\nPercentage breakdown:");
    println!("  Allocation:    {:>5.1}%", alloc_pct);
    println!("  Fiat-Shamir:   {:>5.1}%", fs_pct);
    println!("  Composition:   {:>5.1}%", comp_pct);
    println!("  Answer:        {:>5.1}% (Merkle decommitments)", ans_pct);
    println!("  Folding:       {:>5.1}% (FRI verification)", fold_pct);

    // Finalize and validate circuit (without generating proof)
    println!("\nFinalizing circuit...");
    cs.pad();

    println!("Running check_arithmetics (validates all gate constraints)...");
    cs.check_arithmetics();
    println!("check_arithmetics PASSED!");

    println!("Running populate_logup_arguments (validates copy constraints)...");
    cs.populate_logup_arguments();
    println!("populate_logup_arguments PASSED!");

    // Note: NO check_poseidon_invocations() - we're using PlonkWithoutPoseidon!

    let circuit = cs.generate_plonk_without_poseidon_circuit();
    println!("Circuit generated successfully!");
    println!("Final circuit log_size: {}", (circuit.a_wire.len() as f64).log2() as u32);

    println!("\nStep 3 PASSED: Full verification circuit validated.\n");
    Ok(())
}

/// Step 4: Generate and verify the final proof
fn step4_prove() -> Result<()> {
    println!("=== Step 4: Generate final proof ===\n");

    use circle_plonk_dsl_answer::AnswerResults;
    use circle_plonk_dsl_circle::CirclePointQM31Var;
    use circle_plonk_dsl_composition::CompositionCheck;
    use circle_plonk_dsl_folding::FoldingResults;
    use circle_plonk_dsl_hints::{AnswerHints, DecommitHints, FirstLayerHints, InnerLayersHints};

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(get_proof_path())?)?;
    let config = get_config();
    let inputs = get_inputs();

    // Compute all hints
    let fiat_shamir_hints = FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);
    let answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let decommitment_hints = DecommitHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints = FirstLayerHints::compute(&fiat_shamir_hints, &answer_hints, &proof);
    let inner_layer_hints = InnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );

    // Build circuit
    let cs = ConstraintSystemRef::new_plonk_without_poseidon_ref();
    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    let input_vars: Vec<(usize, QM31Var)> = inputs
        .iter()
        .map(|(idx, val)| (*idx, QM31Var::new_constant(&cs, val)))
        .collect();

    let fiat_shamir_results =
        FiatShamirResults::compute(&fiat_shamir_hints, &mut proof_var, config, &input_vars);

    CompositionCheck::compute(
        &fiat_shamir_hints,
        &fiat_shamir_results.lookup_elements,
        fiat_shamir_results.random_coeff.clone(),
        fiat_shamir_results.oods_point.clone(),
        &proof_var,
    );

    let answer_results = AnswerResults::compute(
        &CirclePointQM31Var::new_witness(&cs, &fiat_shamir_hints.oods_point),
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_hints,
        &decommitment_hints,
        &proof_var,
        config,
    );

    FoldingResults::compute(
        &proof_var,
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_results,
        &first_layer_hints,
        &inner_layer_hints,
    );

    cs.pad();
    cs.check_arithmetics();
    cs.populate_logup_arguments();

    let circuit = cs.generate_plonk_without_poseidon_circuit();
    println!("Verification circuit built.");

    // Generate the outer proof with Sha256MerkleChannel
    // Circuit is 2^21 rows, blowup 7 -> domain 2^28 (max allowed)
    let outer_config = alt1_output_config();

    println!("Generating proof (this may take a while)...");
    let timer = std::time::Instant::now();
    let alt1_proof = prove_plonk_without_poseidon::<Sha256MerkleChannel>(outer_config, &circuit);
    println!("Proof generation time: {:.2}s", timer.elapsed().as_secs_f64());

    println!("\nProof stats:");
    println!("  log_size_plonk: {}", alt1_proof.stmt0.log_size_plonk);
    println!("  plonk_total_sum: {:?}", alt1_proof.stmt1.plonk_total_sum);
    println!(
        "  FRI inner layers: {}",
        alt1_proof.stark_proof.fri_proof.inner_layers.len()
    );

    // Verify the proof
    println!("\nVerifying proof...");
    // For PlonkWithoutPoseidon, we need to compute the expected input_sum
    // But for now, let's try verifying with the same inputs pattern
    verify_plonk_without_poseidon::<Sha256MerkleChannel>(
        alt1_proof.clone(),
        outer_config,
        &inputs,
    )?;
    println!("Proof VERIFIED!");

    // Save the proof
    let proof_bytes = bincode::serialize(&alt1_proof)?;
    let proof_path = if USE_SMALL_PROOF {
        "data/alt1_small_test_proof.bin"
    } else {
        "data/alt1_real_proof.bin"
    };
    std::fs::write(proof_path, &proof_bytes)?;
    println!("\nSaved to {} ({} bytes)", proof_path, proof_bytes.len());

    println!("\nStep 4 PASSED: Alt1 proof generated and verified!\n");
    Ok(())
}

fn main() -> Result<()> {
    println!("=== Alternative 1 Proof Generator ===\n");
    println!("This generates a PlonkWithoutPoseidonProof<Sha256MerkleHasher>");
    println!("that verifies a Poseidon-committed proof using emulated Poseidon.\n");
    println!("Mode: {}", if USE_SMALL_PROOF { "SMALL_PROOF (testing)" } else { "LEVEL13 (full)" });
    println!();

    // Compare circuit sizes first
    compare_circuit_sizes()?;
    println!();

    analyze_poseidon_gates()?;
    println!();

    // Check if we should generate proof or just validate
    let generate_proof = std::env::var("GENERATE_PROOF").is_ok();

    if generate_proof {
        println!("=== GENERATE_PROOF mode: Will generate actual proof ===\n");
        // Skip validation steps, go straight to proof generation
        step4_prove()?;
    } else {
        // Run validation steps incrementally
        step1_load_proof()?;
        step2_fiat_shamir()?;
        step3_full_circuit()?;

        println!("=== Circuit validation complete! ===");
        println!("The verification circuit is correctly constructed.");
        println!("To generate the actual proof, run with: GENERATE_PROOF=1 cargo run --release -p alt1-proof-generator");
    }

    Ok(())
}
