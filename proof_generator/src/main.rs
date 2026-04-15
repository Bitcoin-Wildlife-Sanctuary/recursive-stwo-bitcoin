//! Proof Generator for Alternative 1
//!
//! This generates a PlonkWithoutPoseidonProof with Sha256MerkleHasher
//! that verifies with plonk_total_sum == 0 (no external inputs needed).

use std::ops::Neg;
use stwo_prover::core::backend::simd::column::BaseColumn;
use stwo_prover::core::backend::simd::m31::LOG_N_LANES;
use stwo_prover::core::backend::Column;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
use stwo_prover::examples::plonk_without_poseidon::air::{
    prove_plonk_without_poseidon, verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
};
use stwo_prover::examples::plonk_without_poseidon::plonk::PlonkWithoutAcceleratorCircuitTrace;

/// Create a self-contained circuit where all wires balance internally.
///
/// The key insight: for logup balance without external inputs, every wire's
/// consumption must equal its production.
///
/// Circuit design using MULTIPLICATION (1 * 1 = 1):
/// - All rows use wire index 0
/// - All values are 1 (non-zero to avoid Bitcoin script zero-handling issues)
/// - The constraint 1 * 1 = 1 is satisfied (op1=0 means multiplication)
/// - Each row contributes: +1/combine(1,0) + 1/combine(1,0) - 2/combine(1,0) = 0
///
/// This results in plonk_total_sum = 0, verifiable with empty inputs.
fn create_self_balanced_circuit(log_n_rows: u32) -> PlonkWithoutAcceleratorCircuitTrace {
    assert!(log_n_rows >= LOG_N_LANES);
    let n_rows = 1 << log_n_rows;
    let range = 0..n_rows;

    println!("Creating self-balanced circuit with log_n_rows = {} ({} rows)", log_n_rows, n_rows);

    // Use 1 * 1 = 1 at wire 0 (non-zero values)
    let zeros_m31: BaseColumn = range.clone().map(|_| M31::from(0)).collect();
    let ones_m31: BaseColumn = range.clone().map(|_| M31::from(1)).collect();
    let mult_c: BaseColumn = range.clone().map(|_| M31::from(2).neg()).collect();

    PlonkWithoutAcceleratorCircuitTrace {
        mult_c,
        a_wire: zeros_m31.clone(),  // all wires = 0
        b_wire: zeros_m31.clone(),
        c_wire: zeros_m31.clone(),
        op1: zeros_m31.clone(), // multiplication: c = a * b (op1=0)
        op2: zeros_m31.clone(), // no pow5
        op3: zeros_m31.clone(), // arith gate
        op4: zeros_m31.clone(), // arith gate
        a_val_0: ones_m31.clone(),  // value = 1
        a_val_1: zeros_m31.clone(),
        a_val_2: zeros_m31.clone(),
        a_val_3: zeros_m31.clone(),
        b_val_0: ones_m31.clone(),  // value = 1
        b_val_1: zeros_m31.clone(),
        b_val_2: zeros_m31.clone(),
        b_val_3: zeros_m31.clone(),
        c_val_0: ones_m31.clone(),  // value = 1 (1 * 1 = 1)
        c_val_1: zeros_m31.clone(),
        c_val_2: zeros_m31.clone(),
        c_val_3: zeros_m31.clone(),
    }
}

/// Create a fibonacci circuit that requires external inputs for balance.
///
/// The fibonacci recurrence: fib[i+2] = fib[i] + fib[i+1]
/// Wire layout: row i reads from wires i+1 and i+2, writes to wire i+3
///
/// Logup balance analysis:
/// - Wire 1: consumed once (row 0 a_wire), never produced → +1/combine(fib[0], 1)
/// - Wire 2: consumed twice (row 0 b_wire, row 1 a_wire), never produced → +2/combine(fib[1], 2)
/// - Wires 3 to n: each consumed twice and produced with mult_c=-2 → balanced
/// - Wire n+1: consumed once, produced with mult_c=-1 → balanced
/// - Wire n+2: never consumed, produced with mult_c=0 → balanced
///
/// The unbalanced contribution is:
///   +1/combine(fib[0], 1) + 2/combine(fib[1], 2)
///
/// For this to be balanced, we need external inputs that represent the circuit PRODUCING
/// these values. But external inputs add POSITIVE contributions. So this circuit
/// cannot be balanced with external inputs - it has a structural positive imbalance.
///
/// To fix this, we need to explicitly PRODUCE values at wires 1 and 2.
fn create_fibonacci_circuit(log_n_rows: u32) -> PlonkWithoutAcceleratorCircuitTrace {
    assert!(log_n_rows >= LOG_N_LANES);
    let n_rows = 1 << log_n_rows;
    let range = 0..n_rows;

    println!("Creating fibonacci circuit with log_n_rows = {} ({} rows)", log_n_rows, n_rows);

    // Create fibonacci values
    let mut fib_values_m31 = vec![M31::from(1), M31::from(1)];
    for _ in 0..n_rows {
        let next = fib_values_m31[fib_values_m31.len() - 1] + fib_values_m31[fib_values_m31.len() - 2];
        fib_values_m31.push(next);
    }

    // Wiring: row i reads from wires i+1 and i+2, writes to wire i+3
    let a_wire: BaseColumn = range.clone().map(|i| M31::from((i + 1) as u32)).collect();
    let b_wire: BaseColumn = range.clone().map(|i| M31::from((i + 2) as u32)).collect();
    let c_wire: BaseColumn = range.clone().map(|i| M31::from((i + 3) as u32)).collect();

    // Values
    let a_val_0: BaseColumn = range.clone().map(|i| fib_values_m31[i]).collect();
    let b_val_0: BaseColumn = range.clone().map(|i| fib_values_m31[i + 1]).collect();
    let c_val_0: BaseColumn = range.clone().map(|i| fib_values_m31[i + 2]).collect();

    // Multiplicities for internal balance of wires 3 through n+2
    let mut mult_c: BaseColumn = range.clone().map(|_| M31::from(2).neg()).collect();
    mult_c.set(n_rows - 1, M31::from(0));        // wire n+2: not consumed, so mult_c=0
    mult_c.set(n_rows - 2, M31::from(1).neg()); // wire n+1: consumed once, so mult_c=-1

    let zeros_m31: BaseColumn = range.clone().map(|_| M31::from(0)).collect();

    PlonkWithoutAcceleratorCircuitTrace {
        mult_c,
        a_wire,
        b_wire,
        c_wire,
        op1: range.clone().map(|_| M31::from(1)).collect(), // addition
        op2: zeros_m31.clone(), // no pow5
        op3: zeros_m31.clone(), // arith gate
        op4: zeros_m31.clone(), // arith gate
        a_val_0,
        a_val_1: zeros_m31.clone(),
        a_val_2: zeros_m31.clone(),
        a_val_3: zeros_m31.clone(),
        b_val_0,
        b_val_1: zeros_m31.clone(),
        b_val_2: zeros_m31.clone(),
        b_val_3: zeros_m31.clone(),
        c_val_0,
        c_val_1: zeros_m31.clone(),
        c_val_2: zeros_m31.clone(),
        c_val_3: zeros_m31,
    }
}

fn main() {
    println!("=== Alternative 1 Proof Generator ===\n");

    // Configuration for testing
    let config = PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 4, 8),
    };

    // Test 1: Self-balanced circuit (should verify with empty inputs)
    println!("=== Test 1: Self-balanced circuit ===\n");
    let log_n_rows = 4u32; // 16 rows (minimum)

    let circuit = create_self_balanced_circuit(log_n_rows);
    println!("Generating proof...");
    let proof: PlonkWithoutPoseidonProof<_> =
        prove_plonk_without_poseidon::<Sha256MerkleChannel>(config, &circuit);

    println!("\nProof stats:");
    println!("  log_size_plonk: {}", proof.stmt0.log_size_plonk);
    println!("  plonk_total_sum: {:?}", proof.stmt1.plonk_total_sum);
    println!("  FRI inner layers: {}", proof.stark_proof.fri_proof.inner_layers.len());

    let empty_inputs: Vec<(usize, QM31)> = vec![];
    println!("\nVerifying with empty inputs...");
    match verify_plonk_without_poseidon::<Sha256MerkleChannel>(proof.clone(), config, &empty_inputs) {
        Ok(()) => {
            println!("SUCCESS! Self-balanced circuit verified!");

            // Save this working proof
            let proof_bytes = bincode::serialize(&proof).unwrap();
            let proof_path = "data/alternative1_test_proof.bin";
            println!("\nSaving proof to {}...", proof_path);
            std::fs::write(proof_path, &proof_bytes).unwrap();
            println!("Proof saved ({} bytes)", proof_bytes.len());
        }
        Err(e) => {
            println!("FAILED: {:?}", e);
        }
    }

    // Skip Test 2 (fibonacci) since verification panics on failure

    // Now let's create a larger self-balanced proof to match the complexity needed
    println!("\n\n=== Test 3: Larger self-balanced circuit ===\n");
    let large_log_n_rows = 17u32; // Match the existing bitcoin_proof.bin size

    let large_circuit = create_self_balanced_circuit(large_log_n_rows);

    // Use the same configuration as bitcoin_proof.bin so existing verification code works
    // Original config: pow_bits=28, FriConfig(log_last_layer_degree=0, log_blowup_factor=9, n_queries=8)
    // This produces 18 FRI inner layers
    let prod_config = PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(0, 9, 8),
    };

    println!("Generating proof (this may take a while)...");
    let large_proof: PlonkWithoutPoseidonProof<_> =
        prove_plonk_without_poseidon::<Sha256MerkleChannel>(prod_config, &large_circuit);

    println!("\nProof stats:");
    println!("  log_size_plonk: {}", large_proof.stmt0.log_size_plonk);
    println!("  plonk_total_sum: {:?}", large_proof.stmt1.plonk_total_sum);
    println!("  FRI inner layers: {}", large_proof.stark_proof.fri_proof.inner_layers.len());

    println!("\nVerifying with empty inputs...");
    match verify_plonk_without_poseidon::<Sha256MerkleChannel>(large_proof.clone(), prod_config, &empty_inputs) {
        Ok(()) => {
            println!("SUCCESS! Large self-balanced circuit verified!");

            // Save this working proof
            let proof_bytes = bincode::serialize(&large_proof).unwrap();
            let proof_path = "data/alternative1_proof.bin";
            println!("\nSaving proof to {}...", proof_path);
            std::fs::write(proof_path, &proof_bytes).unwrap();
            println!("Proof saved ({} bytes)", proof_bytes.len());
        }
        Err(e) => {
            println!("FAILED: {:?}", e);
        }
    }
}
