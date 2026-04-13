use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

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

    println!("=== Analysis ===");
    println!("The outer proof (hybrid_hash.bin) has log_size_plonk={} and log_size_poseidon={}",
             proof_outer.stmt0.log_size_plonk, proof_outer.stmt0.log_size_poseidon);
    println!("The inner proof (bitcoin_proof.bin) has log_size_plonk={}",
             proof_inner.stmt0.log_size_plonk);
    println!();
    println!("For Alternative 1, a new proof would need to:");
    println!("  1. Have plonk_total_sum = 0 (no delegation inputs)");
    println!("  2. Potentially have different log_size_plonk if proving more computation");
    println!("  3. Use pure SHA256 Merkle hasher");
}
