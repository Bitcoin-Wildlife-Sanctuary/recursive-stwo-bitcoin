use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

fn inspect_pwp_sampled_values(proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>) {
    println!("\n=== Detailed sampled_values structure ===");
    for (tree_idx, tree) in proof.stark_proof.sampled_values.iter().enumerate() {
        let tree_name = match tree_idx {
            0 => "preprocessed",
            1 => "trace",
            2 => "interaction",
            3 => "composition",
            _ => "unknown",
        };
        println!("\ntree[{}] ({}): {} columns", tree_idx, tree_name, tree.len());
        for (col_idx, col) in tree.iter().enumerate() {
            if col.len() > 0 {
                println!("  col[{}]: {} samples, first={:?}", col_idx, col.len(), col[0]);
            } else {
                println!("  col[{}]: 0 samples", col_idx);
            }
        }
    }
}

fn main() {
    println!("=== Inspecting hybrid_hash.bin (PlonkWithPoseidon, outer proof) ===");
    let proof_outer: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
        bincode::deserialize(include_bytes!("../../../data/hybrid_hash.bin")).unwrap();

    println!("  log_size_plonk: {}", proof_outer.stmt0.log_size_plonk);
    println!("  log_size_poseidon: {}", proof_outer.stmt0.log_size_poseidon);
    println!("  plonk_total_sum: {:?}", proof_outer.stmt1.plonk_total_sum);
    println!("  poseidon_total_sum: {:?}", proof_outer.stmt1.poseidon_total_sum);
    println!("  num commitments: {}", proof_outer.stark_proof.commitments.len());
    println!("  FRI first layer commitment: present");
    println!("  FRI inner layers: {}", proof_outer.stark_proof.fri_proof.inner_layers.len());
    println!("  FRI last layer poly log_size: {}", proof_outer.stark_proof.fri_proof.last_layer_poly.log_size);
    println!();

    println!("=== Inspecting bitcoin_proof.bin (PlonkWithoutPoseidon, inner proof) ===");
    let proof_inner: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
        bincode::deserialize(include_bytes!("../../../data/bitcoin_proof.bin")).unwrap();

    println!("  log_size_plonk: {}", proof_inner.stmt0.log_size_plonk);
    println!("  plonk_total_sum: {:?}", proof_inner.stmt1.plonk_total_sum);
    println!("  num commitments: {}", proof_inner.stark_proof.commitments.len());
    println!("  FRI first layer commitment: present");
    println!("  FRI inner layers: {}", proof_inner.stark_proof.fri_proof.inner_layers.len());
    println!("  FRI last layer poly log_size: {}", proof_inner.stark_proof.fri_proof.last_layer_poly.log_size);
    println!();

    println!("=== Inspecting alternative1_proof.bin (PlonkWithoutPoseidon, self-balanced) ===");
    let proof_alt1: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
        bincode::deserialize(include_bytes!("../../../data/alternative1_proof.bin")).unwrap();

    println!("  log_size_plonk: {}", proof_alt1.stmt0.log_size_plonk);
    println!("  plonk_total_sum: {:?}", proof_alt1.stmt1.plonk_total_sum);
    println!("  num commitments: {}", proof_alt1.stark_proof.commitments.len());
    println!("  FRI first layer commitment: present");
    println!("  FRI inner layers: {}", proof_alt1.stark_proof.fri_proof.inner_layers.len());
    println!("  FRI last layer poly log_size: {}", proof_alt1.stark_proof.fri_proof.last_layer_poly.log_size);
    println!();

    println!("=== Comparison ===");
    println!("bitcoin_proof.bin: plonk_total_sum = {:?}", proof_inner.stmt1.plonk_total_sum);
    println!("alternative1_proof.bin: plonk_total_sum = {:?}", proof_alt1.stmt1.plonk_total_sum);
    println!();

    println!("=== Detailed sampled_values comparison ===");
    println!("bitcoin_proof sampled_values structure:");
    for (tree_idx, tree) in proof_inner.stark_proof.sampled_values.iter().enumerate() {
        for (col_idx, col) in tree.iter().enumerate() {
            println!("  tree[{}][{}]: {} samples", tree_idx, col_idx, col.len());
            if col.len() > 0 {
                println!("    first sample: {:?}", col[0]);
            }
        }
    }

    println!("\nalternative1_proof sampled_values structure:");
    for (tree_idx, tree) in proof_alt1.stark_proof.sampled_values.iter().enumerate() {
        for (col_idx, col) in tree.iter().enumerate() {
            println!("  tree[{}][{}]: {} samples", tree_idx, col_idx, col.len());
            if col.len() > 0 {
                println!("    first sample: {:?}", col[0]);
            }
        }
    }

    println!();
    println!("Alternative 1 has plonk_total_sum = 0, meaning no external inputs needed.");

    // Inspect poseidon_accelerated_proof.bin if it exists
    if let Ok(proof_bytes) = std::fs::read("data/poseidon_accelerated_proof.bin") {
        println!("\n=== Inspecting poseidon_accelerated_proof.bin (PlonkWithPoseidon, SHA256 channel) ===");
        let proof_pwp: PlonkWithPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(&proof_bytes).unwrap();

        println!("  log_size_plonk: {}", proof_pwp.stmt0.log_size_plonk);
        println!("  log_size_poseidon: {}", proof_pwp.stmt0.log_size_poseidon);
        println!("  plonk_total_sum: {:?}", proof_pwp.stmt1.plonk_total_sum);
        println!("  poseidon_total_sum: {:?}", proof_pwp.stmt1.poseidon_total_sum);
        println!("  num commitments: {}", proof_pwp.stark_proof.commitments.len());
        println!("  FRI first layer commitment: present");
        println!("  FRI inner layers: {}", proof_pwp.stark_proof.fri_proof.inner_layers.len());
        println!("  FRI last layer poly log_size: {}", proof_pwp.stark_proof.fri_proof.last_layer_poly.log_size);

        inspect_pwp_sampled_values(&proof_pwp);
    } else {
        println!("\nposeidon_accelerated_proof.bin not found - run poseidon-proof-generator first");
    }
}
