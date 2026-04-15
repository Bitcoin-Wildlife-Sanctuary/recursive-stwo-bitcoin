//! Answer hints for PlonkWithPoseidon Bitcoin script verification
//!
//! This module computes FRI answers at query positions for PlonkWithPoseidon proofs.

use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
use itertools::Itertools;
use std::iter::zip;
use std::marker::PhantomData;
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::pcs::quotients::{fri_answers, PointSample};
use stwo_prover::core::ColumnVec;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

/// FRI answer hints for PlonkWithPoseidon proofs
pub struct PwpAnswerHints<MC: MerkleChannel> {
    /// Computed FRI answers at each query position, per log_size
    pub fri_answers: ColumnVec<Vec<SecureField>>,
    pub phantom: PhantomData<MC>,
}

impl<MC: MerkleChannel> PwpAnswerHints<MC> {
    pub fn compute(
        fiat_shamir_hints: &PwpFiatShamirHints<MC>,
        proof: &PlonkWithPoseidonProof<MC::H>,
    ) -> Self {
        // Answer FRI queries.
        // Create point samples from sample_points and sampled_values
        let samples = fiat_shamir_hints
            .sample_points
            .clone()
            .zip_cols(proof.stark_proof.sampled_values.clone())
            .map_cols(|(sampled_points, sampled_values)| {
                zip(sampled_points, sampled_values)
                    .map(|(point, value)| PointSample { point, value })
                    .collect_vec()
            });

        // Compute FRI answers using stwo's quotient evaluation
        let fri_answers = fri_answers(
            fiat_shamir_hints.column_log_sizes.clone(),
            samples,
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.sorted_query_positions_per_log_size,
            proof.stark_proof.queried_values.clone(),
            fiat_shamir_hints.n_columns_per_log_size.as_ref(),
        )
        .unwrap();

        Self {
            fri_answers,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};

    #[test]
    fn test_pwp_answer_hints() {
        let proof_bytes = std::fs::read("../data/poseidon_accelerated_proof.bin")
            .expect("Failed to load proof");
        let proof: PlonkWithPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(&proof_bytes).unwrap();

        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };
        let inputs: Vec<(usize, stwo_prover::core::fields::qm31::QM31)> = vec![];

        let fiat_shamir_hints =
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config, &inputs);

        // Debug: print structure sizes
        println!("=== Debug: Proof structure ===");
        println!("n_columns_per_log_size trees: {}", fiat_shamir_hints.n_columns_per_log_size.len());
        for (i, tree) in fiat_shamir_hints.n_columns_per_log_size.iter().enumerate() {
            println!("  Tree {}: {:?}", i, tree);
        }
        println!("queried_values trees: {}", proof.stark_proof.queried_values.len());
        for (i, tree) in proof.stark_proof.queried_values.iter().enumerate() {
            println!("  Tree {}: {} values", i, tree.len());
        }
        println!("sample_points trees: {}", fiat_shamir_hints.sample_points.len());
        for (i, tree) in fiat_shamir_hints.sample_points.iter().enumerate() {
            println!("  Tree {}: {} columns", i, tree.len());
            for (j, col) in tree.iter().enumerate().take(5) {
                println!("    Col {}: {} points", j, col.len());
            }
            if tree.len() > 5 {
                println!("    ... and {} more columns", tree.len() - 5);
            }
        }
        println!("sampled_values trees: {}", proof.stark_proof.sampled_values.len());
        for (i, tree) in proof.stark_proof.sampled_values.iter().enumerate() {
            println!("  Tree {}: {} columns", i, tree.len());
            for (j, col) in tree.iter().enumerate().take(5) {
                println!("    Col {}: {} values", j, col.len());
            }
            if tree.len() > 5 {
                println!("    ... and {} more columns", tree.len() - 5);
            }
        }

        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        println!("=== PwpAnswerHints ===");
        println!("fri_answers log_sizes: {}", answer_hints.fri_answers.len());
        for (i, col) in answer_hints.fri_answers.iter().enumerate() {
            println!("  log_size {}: {} answers", i, col.len());
        }

        println!("\nPwpAnswerHints test passed!");
    }
}
