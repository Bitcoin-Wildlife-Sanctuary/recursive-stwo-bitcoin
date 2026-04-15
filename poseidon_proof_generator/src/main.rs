//! Poseidon Accelerated Proof Generator
//!
//! Generates PlonkWithPoseidonProof<Sha256MerkleHasher> that verifies level13-1.bin
//! using the native Poseidon accelerator (48-column sub-circuit).
//!
//! Key difference from alt1_proof_generator:
//! - Uses PlonkWithPoseidon constraint system (native Poseidon accelerator)
//! - Results in much smaller circuit (~2^15 vs ~2^21 rows)
//! - But proof has more columns (~130 vs ~28)
//!
//! Output is Bitcoin-verifiable (pure SHA256 channel).

use anyhow::Result;
use circle_plonk_dsl_answer::AnswerResults;
use circle_plonk_dsl_circle::CirclePointQM31Var;
use circle_plonk_dsl_composition::CompositionCheck;
use circle_plonk_dsl_constraint_system::var::AllocVar;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_data_structures::PlonkWithPoseidonProofVar;
use circle_plonk_dsl_fields::QM31Var;
use circle_plonk_dsl_fiat_shamir::FiatShamirResults;
use circle_plonk_dsl_folding::FoldingResults;
use circle_plonk_dsl_hints::{
    AnswerHints, DecommitHints, FiatShamirHints, FirstLayerHints, InnerLayersHints,
};
use num_traits::One;
use std::io::Write;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::poseidon31_merkle::{Poseidon31MerkleChannel, Poseidon31MerkleHasher};
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
use stwo_prover::examples::plonk_with_poseidon::air::{
    prove_plonk_with_poseidon, verify_plonk_with_poseidon, PlonkWithPoseidonProof,
};

/// Path to level13-1.bin (the input proof we want to verify)
const LEVEL13_PROOF_PATH: &str = concat!(
    env!("HOME"),
    "/.cargo/git/checkouts/recursive-stwo-9c7bf9c393de374c/caea77f/examples/multi-proofs/data/level13-1.bin"
);

/// PCS config for READING level13-1.bin (the input proof)
fn level13_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    }
}

/// PCS config for the OUTPUT proof (PlonkWithPoseidon with Sha256MerkleChannel)
/// Circuit should be ~2^15 rows, so we have more flexibility with blowup factor
fn output_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8), // Same as level13 for now
    }
}

fn get_inputs() -> Vec<(usize, QM31)> {
    vec![
        (1, QM31::one()),
        (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
        (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
    ]
}

/// Step 1: Load proof and inspect structure
fn step1_load_and_inspect() -> Result<()> {
    println!("=== Step 1: Load level13-1.bin and inspect ===\n");

    let proof_bytes = std::fs::read(LEVEL13_PROOF_PATH)?;
    println!("Loaded {} bytes from level13-1.bin", proof_bytes.len());

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&proof_bytes)?;

    println!("\nInput proof structure:");
    println!("  log_size_plonk: {}", proof.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof.stmt0.log_size_poseidon);
    println!("  plonk_total_sum: {:?}", proof.stmt1.plonk_total_sum);
    println!("  poseidon_total_sum: {:?}", proof.stmt1.poseidon_total_sum);
    println!("  num commitments: {}", proof.stark_proof.commitments.len());
    println!(
        "  FRI inner layers: {}",
        proof.stark_proof.fri_proof.inner_layers.len()
    );

    // Show sampled_values structure
    println!("\n  sampled_values structure:");
    for (tree_idx, tree) in proof.stark_proof.sampled_values.iter().enumerate() {
        println!("    tree[{}]: {} columns", tree_idx, tree.len());
    }

    println!("\nStep 1 PASSED.\n");
    Ok(())
}

/// Step 2: Allocate proof variables under PlonkWithPoseidon CS
fn step2_allocate() -> Result<()> {
    println!("=== Step 2: Allocate proof variables under PlonkWithPoseidon CS ===\n");

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(LEVEL13_PROOF_PATH)?)?;

    // Use PlonkWithPoseidon constraint system (has native Poseidon accelerator)
    let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();

    println!("CS type: {:?}", cs.get_type());

    let rows_before = cs.num_plonk_rows();
    let poseidon_before = cs.num_poseidon_invocations();

    let _proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    let rows_after = cs.num_plonk_rows();
    let poseidon_after = cs.num_poseidon_invocations();

    println!("After proof allocation:");
    println!("  PLONK rows: {} (+{})", rows_after, rows_after - rows_before);
    println!(
        "  Poseidon invocations: {} (+{})",
        poseidon_after,
        poseidon_after - poseidon_before
    );

    println!("\nStep 2 PASSED.\n");
    Ok(())
}

/// Step 3: Run Fiat-Shamir with native Poseidon
fn step3_fiat_shamir() -> Result<()> {
    println!("=== Step 3: Fiat-Shamir with native Poseidon ===\n");

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(LEVEL13_PROOF_PATH)?)?;
    let config = level13_config();
    let inputs = get_inputs();

    // Compute Fiat-Shamir hints
    println!("Computing Fiat-Shamir hints...");
    let fiat_shamir_hints =
        FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);

    println!("  z: {:?}", fiat_shamir_hints.z);
    println!("  alpha: {:?}", fiat_shamir_hints.alpha);
    println!(
        "  fri_alphas count: {}",
        fiat_shamir_hints.fri_alphas.len()
    );

    // Run in PlonkWithPoseidon circuit
    let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();
    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    let rows_before = cs.num_plonk_rows();
    let poseidon_before = cs.num_poseidon_invocations();

    let input_vars: Vec<(usize, QM31Var)> = inputs
        .iter()
        .map(|(idx, val)| (*idx, QM31Var::new_constant(&cs, val)))
        .collect();

    let fiat_shamir_results =
        FiatShamirResults::compute(&fiat_shamir_hints, &mut proof_var, config, &input_vars);

    let rows_after = cs.num_plonk_rows();
    let poseidon_after = cs.num_poseidon_invocations();

    println!("\nAfter Fiat-Shamir:");
    println!(
        "  PLONK rows: {} (+{})",
        rows_after,
        rows_after - rows_before
    );
    println!(
        "  Poseidon invocations: {} (+{})",
        poseidon_after,
        poseidon_after - poseidon_before
    );

    // Verify values match
    println!(
        "\n  z matches: {}",
        fiat_shamir_results.lookup_elements.z.value() == fiat_shamir_hints.z
    );
    println!(
        "  alpha matches: {}",
        fiat_shamir_results.lookup_elements.alpha.value() == fiat_shamir_hints.alpha
    );

    println!("\nStep 3 PASSED.\n");
    Ok(())
}

/// Step 4: Full verification circuit with detailed breakdown
fn step4_full_circuit() -> Result<()> {
    println!("=== Step 4: Full verification circuit ===\n");

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(LEVEL13_PROOF_PATH)?)?;
    let config = level13_config();
    let inputs = get_inputs();

    // Compute all hints
    println!("Computing all hints...");
    let fiat_shamir_hints =
        FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);
    let answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let decommitment_hints = DecommitHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints = FirstLayerHints::compute(&fiat_shamir_hints, &answer_hints, &proof);
    let inner_layer_hints = InnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );
    println!("All hints computed.\n");

    // Build circuit with PlonkWithPoseidon
    println!("--- Gate Count Breakdown (PlonkWithPoseidon) ---\n");
    let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();

    // Track both PLONK rows and Poseidon invocations
    let mut track = |name: &str, cs: &ConstraintSystemRef| {
        println!(
            "{}: {} PLONK rows, {} Poseidon invocations",
            name,
            cs.num_plonk_rows(),
            cs.num_poseidon_invocations()
        );
    };

    track("Initial", &cs);

    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);
    track("After proof allocation", &cs);

    let input_vars: Vec<(usize, QM31Var)> = inputs
        .iter()
        .map(|(idx, val)| (*idx, QM31Var::new_constant(&cs, val)))
        .collect();

    let fiat_shamir_results =
        FiatShamirResults::compute(&fiat_shamir_hints, &mut proof_var, config, &input_vars);
    track("After Fiat-Shamir", &cs);

    CompositionCheck::compute(
        &fiat_shamir_hints,
        &fiat_shamir_results.lookup_elements,
        fiat_shamir_results.random_coeff.clone(),
        fiat_shamir_results.oods_point.clone(),
        &proof_var,
    );
    track("After Composition", &cs);

    let answer_results = AnswerResults::compute(
        &CirclePointQM31Var::new_witness(&cs, &fiat_shamir_hints.oods_point),
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_hints,
        &decommitment_hints,
        &proof_var,
        config,
    );
    track("After Answer", &cs);

    FoldingResults::compute(
        &proof_var,
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_results,
        &first_layer_hints,
        &inner_layer_hints,
    );
    track("After Folding", &cs);

    // Validate circuit
    println!("\n--- Validating Circuit ---\n");

    println!("Running cs.pad()...");
    cs.pad();

    println!("Running check_arithmetics()...");
    cs.check_arithmetics();
    println!("check_arithmetics PASSED!");

    println!("Running populate_logup_arguments()...");
    cs.populate_logup_arguments();
    println!("populate_logup_arguments PASSED!");

    println!("Running check_poseidon_invocations()...");
    cs.check_poseidon_invocations();
    println!("check_poseidon_invocations PASSED!");

    // Generate circuit (but don't prove yet)
    println!("\nGenerating PlonkWithPoseidon circuit...");
    let (plonk_circuit, poseidon_flow) = cs.generate_plonk_with_poseidon_circuit();

    // Get circuit sizes from the circuit structures
    let plonk_log_size = plonk_circuit.mult_c.length.ilog2();
    // Poseidon log_size: flow has N entries, each expands to 8 rows (LOG_EXPAND=3)
    let padded_n_instances = poseidon_flow.0.len().next_power_of_two();
    let poseidon_log_size = (padded_n_instances * 8).ilog2();

    println!("\n--- Circuit Summary ---");
    println!("PLONK circuit log_size: {} (2^{} = {} rows)", plonk_log_size, plonk_log_size, 1u64 << plonk_log_size);
    println!("Poseidon circuit log_size: {} (2^{} = {} rows)", poseidon_log_size, poseidon_log_size, 1u64 << poseidon_log_size);
    println!("Poseidon invocations: {}", poseidon_flow.0.len());

    // Compare with PlonkWithoutPoseidon (alt1)
    println!("\n--- Comparison with PlonkWithoutPoseidon (alt1) ---");
    println!("PlonkWithoutPoseidon: 2^21 = 2,097,152 rows (emulated Poseidon)");
    println!("PlonkWithPoseidon:    2^{} = {} PLONK rows + 2^{} = {} Poseidon rows",
        plonk_log_size, 1u64 << plonk_log_size,
        poseidon_log_size, 1u64 << poseidon_log_size);

    let alt1_rows = 1u64 << 21;
    let this_plonk_rows = 1u64 << plonk_log_size;
    println!("PLONK row reduction: {:.1}x smaller", alt1_rows as f64 / this_plonk_rows as f64);

    println!("\nStep 4 PASSED: Circuit validated successfully.\n");
    Ok(())
}

/// Step 5: Generate the actual proof
fn step5_prove() -> Result<()> {
    println!("=== Step 5: Generate PlonkWithPoseidonProof<Sha256MerkleHasher> ===\n");

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize(&std::fs::read(LEVEL13_PROOF_PATH)?)?;
    let config = level13_config();
    let inputs = get_inputs();

    // Compute all hints
    println!("Computing hints...");
    let fiat_shamir_hints =
        FiatShamirHints::<Poseidon31MerkleChannel>::new(&proof, config, &inputs);
    let answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let decommitment_hints = DecommitHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints = FirstLayerHints::compute(&fiat_shamir_hints, &answer_hints, &proof);
    let inner_layer_hints = InnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );

    // Build circuit
    println!("Building verification circuit...");
    let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();

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
    cs.check_poseidon_invocations();

    let (plonk_circuit, mut poseidon_flow) = cs.generate_plonk_with_poseidon_circuit();

    // Get circuit sizes from the circuit structures
    let plonk_log_size = plonk_circuit.mult_c.length.ilog2();
    let padded_n_instances = poseidon_flow.0.len().next_power_of_two();
    let poseidon_log_size = (padded_n_instances * 8).ilog2();
    println!("Circuit sizes: PLONK 2^{}, Poseidon 2^{} ({} invocations)",
        plonk_log_size, poseidon_log_size, poseidon_flow.0.len());

    // Generate proof with Sha256MerkleChannel (Bitcoin-verifiable)
    let outer_config = output_config();
    println!("\nGenerating proof with Sha256MerkleChannel...");
    println!("  pow_bits: {}", outer_config.pow_bits);
    println!("  fri_config: log_last_layer={}, log_blowup={}, n_queries={}",
        outer_config.fri_config.log_last_layer_degree_bound,
        outer_config.fri_config.log_blowup_factor,
        outer_config.fri_config.n_queries);

    let timer = std::time::Instant::now();
    let output_proof = prove_plonk_with_poseidon::<Sha256MerkleChannel>(
        outer_config,
        &plonk_circuit,
        &mut poseidon_flow,
    );
    let prove_time = timer.elapsed();
    println!("Proof generation time: {:.2}s", prove_time.as_secs_f64());

    // Show output proof structure
    println!("\n--- Output Proof Structure ---");
    println!("  log_size_plonk: {}", output_proof.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", output_proof.stmt0.log_size_poseidon);
    println!("  plonk_total_sum: {:?}", output_proof.stmt1.plonk_total_sum);
    println!("  poseidon_total_sum: {:?}", output_proof.stmt1.poseidon_total_sum);
    println!("  num commitments: {}", output_proof.stark_proof.commitments.len());
    println!("  FRI inner layers: {}", output_proof.stark_proof.fri_proof.inner_layers.len());

    // Show sampled_values structure (this is what Bitcoin scripts verify)
    println!("\n  sampled_values structure:");
    for (tree_idx, tree) in output_proof.stark_proof.sampled_values.iter().enumerate() {
        let total_samples: usize = tree.iter().map(|c| c.len()).sum();
        println!("    tree[{}]: {} columns, {} total samples", tree_idx, tree.len(), total_samples);
    }

    // Verify the proof
    println!("\nVerifying proof...");
    verify_plonk_with_poseidon::<Sha256MerkleChannel>(
        output_proof.clone(),
        outer_config,
        &inputs,
    )?;
    println!("Proof VERIFIED!");

    // Save the proof
    let proof_bytes = bincode::serialize(&output_proof)?;
    let proof_path = "data/poseidon_accelerated_proof.bin";

    // Ensure data directory exists
    std::fs::create_dir_all("data")?;

    let mut file = std::fs::File::create(proof_path)?;
    file.write_all(&proof_bytes)?;
    println!("\nSaved to {} ({} bytes)", proof_path, proof_bytes.len());

    println!("\nStep 5 PASSED: Proof generated and verified!\n");
    Ok(())
}

fn main() -> Result<()> {
    println!("==============================================");
    println!("  Poseidon Accelerated Proof Generator");
    println!("==============================================\n");
    println!("Generates PlonkWithPoseidonProof<Sha256MerkleHasher>");
    println!("that verifies level13-1.bin using native Poseidon accelerator.\n");
    println!("This is Bitcoin-verifiable (pure SHA256 channel).\n");

    // Check mode
    let generate_proof = std::env::var("GENERATE_PROOF").is_ok();

    if generate_proof {
        println!("=== GENERATE_PROOF mode ===\n");
        step5_prove()?;
    } else {
        println!("=== VALIDATION mode (run with GENERATE_PROOF=1 to generate proof) ===\n");

        step1_load_and_inspect()?;
        step2_allocate()?;
        step3_fiat_shamir()?;
        step4_full_circuit()?;

        println!("==============================================");
        println!("  Validation Complete!");
        println!("==============================================\n");
        println!("Circuit is correctly constructed and validated.");
        println!("To generate the actual proof, run:");
        println!("  GENERATE_PROOF=1 cargo run --release -p poseidon-proof-generator");
    }

    Ok(())
}
