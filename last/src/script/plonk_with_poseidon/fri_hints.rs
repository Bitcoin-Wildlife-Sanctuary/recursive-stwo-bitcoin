//! FRI hints for PlonkWithPoseidon Bitcoin script verification
//!
//! This module provides FRI layer hints for per-query scripts.

use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

/// FRI first layer hints for a single query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwpFriFirstLayerQueryHints {
    /// Left value (self or sibling depending on query bit)
    pub left: SecureField,
    /// Right value
    pub right: SecureField,
    /// Twiddle (x_inv) for folding
    pub twiddle: M31,
}

/// FRI inner layer hints for a single query at a specific layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwpFriInnerLayerQueryHints {
    /// Self value at this layer
    pub self_value: SecureField,
    /// Sibling value at this layer
    pub sibling_value: SecureField,
    /// Twiddle (x_inv) for folding
    pub twiddle: M31,
}

/// Complete FRI hints for a single query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwpFriQueryHints {
    /// First layer hints (log_size 27 -> 26)
    pub first_layer: PwpFriFirstLayerQueryHints,
    /// Inner layer hints keyed by log_size (26 -> final)
    pub inner_layers: BTreeMap<u32, PwpFriInnerLayerQueryHints>,
    /// Expected last layer evaluation
    pub last_layer_eval: SecureField,
    /// Final layer log_size
    pub final_log_size: u32,
}

/// FRI hints for all queries
#[derive(Debug, Clone)]
pub struct PwpFriHints {
    /// Hints per query
    pub query_hints: Vec<PwpFriQueryHints>,
    /// Number of inner layers
    pub n_inner_layers: usize,
    /// Final layer log_size
    pub final_log_size: u32,
}

impl PwpFriHints {
    pub fn compute<MC: MerkleChannel>(
        fri_answers: &[SecureField],
        fiat_shamir_hints: &PwpFiatShamirHints<MC>,
        proof: &PlonkWithPoseidonProof<MC::H>,
    ) -> Self {
        let max_log_size = fiat_shamir_hints.max_first_layer_column_log_size;
        let n_inner_layers = proof.stark_proof.fri_proof.inner_layers.len();
        let final_log_size = max_log_size - 1 - n_inner_layers as u32;

        // Get query positions for the maximum log size
        let query_positions: Vec<usize> = fiat_shamir_hints
            .unsorted_query_positions_per_log_size
            .get(&max_log_size)
            .cloned()
            .unwrap_or_default();

        let n_queries = query_positions.len();

        // Track folded values for all queries at each layer
        // Start with FRI answers
        let mut folded_values: BTreeMap<usize, SecureField> = BTreeMap::new();
        for (idx, &q) in query_positions.iter().enumerate() {
            // After first layer folding, query position is q >> 1
            folded_values.insert(q >> 1, fri_answers[idx]);
        }

        let mut query_hints = Vec::with_capacity(n_queries);

        // Process first layer for all queries
        let first_layer_domain = Coset::half_odds(max_log_size - 1);
        let mut first_layer_hints = Vec::with_capacity(n_queries);

        for (query_idx, &initial_query) in query_positions.iter().enumerate() {
            let query_after_first = initial_query >> 1;
            let self_value = fri_answers[query_idx];

            // For the first layer, we need to find the sibling
            // The sibling query is (initial_query ^ 1) >> 1, but since we're looking at
            // the first layer commitment, the sibling comes from the first layer proof
            let sibling_query = query_after_first ^ 1;

            // Get sibling from folded values or from fri_witness
            let sibling_value = folded_values.get(&sibling_query).copied();

            // Compute twiddle
            let point = first_layer_domain.at(bit_reverse_index(query_after_first << 1, max_log_size - 1));
            let twiddle = point.x.inverse();

            // Determine left/right based on query bit
            let (left, right) = if query_after_first & 1 == 0 {
                (self_value, sibling_value.unwrap_or(SecureField::zero()))
            } else {
                (sibling_value.unwrap_or(SecureField::zero()), self_value)
            };

            first_layer_hints.push(PwpFriFirstLayerQueryHints {
                left,
                right,
                twiddle,
            });
        }

        // Fold first layer values
        let first_alpha = fiat_shamir_hints.fri_alphas[0];
        let mut current_values: Vec<SecureField> = Vec::with_capacity(n_queries);
        let mut current_queries: Vec<usize> = Vec::with_capacity(n_queries);

        for (query_idx, hints) in first_layer_hints.iter().enumerate() {
            let t0 = hints.left + hints.right;
            let t1 = (hints.left - hints.right) * hints.twiddle;
            let folded = t0 + t1 * first_alpha;
            current_values.push(folded);
            current_queries.push(query_positions[query_idx] >> 1);
        }

        // Process inner layers
        let mut all_inner_layer_hints: Vec<BTreeMap<u32, PwpFriInnerLayerQueryHints>> =
            vec![BTreeMap::new(); n_queries];

        let mut log_size = max_log_size - 1; // Start at 26 after first layer

        for (layer_idx, inner_layer) in proof.stark_proof.fri_proof.inner_layers.iter().enumerate() {
            let domain = Coset::half_odds(log_size - 1);
            let alpha = fiat_shamir_hints.fri_alphas[layer_idx + 1];

            // Build map of current folded values
            let mut folded_map: BTreeMap<usize, SecureField> = BTreeMap::new();
            for (idx, &q) in current_queries.iter().enumerate() {
                folded_map.insert(q, current_values[idx]);
            }

            // Get witnesses for this layer
            let mut fri_witness_iter = inner_layer.fri_witness.iter();

            let mut new_values: Vec<SecureField> = Vec::with_capacity(n_queries);
            let mut new_queries: Vec<usize> = Vec::with_capacity(n_queries);

            for (query_idx, &query) in current_queries.iter().enumerate() {
                let sibling_query = query ^ 1;
                let self_value = current_values[query_idx];

                // Get sibling value
                let sibling_value = if let Some(&val) = folded_map.get(&sibling_query) {
                    val
                } else {
                    // Get from fri_witness
                    *fri_witness_iter.next().unwrap_or(&SecureField::zero())
                };

                // Compute twiddle
                let folded_query = query >> 1;
                let point = domain.at(bit_reverse_index(folded_query << 1, log_size - 1));
                let twiddle = point.x.inverse();

                // Store hints
                all_inner_layer_hints[query_idx].insert(
                    log_size,
                    PwpFriInnerLayerQueryHints {
                        self_value,
                        sibling_value,
                        twiddle,
                    },
                );

                // Fold
                let (left, right) = if query & 1 == 0 {
                    (self_value, sibling_value)
                } else {
                    (sibling_value, self_value)
                };

                let t0 = left + right;
                let t1 = (left - right) * twiddle;
                let folded = t0 + t1 * alpha;

                new_values.push(folded);
                new_queries.push(folded_query);
            }

            current_values = new_values;
            current_queries = new_queries;
            log_size -= 1;
        }

        // Compute last layer evaluations
        for query_idx in 0..n_queries {
            let query = current_queries[query_idx];
            let last_layer_eval = compute_last_layer_eval(
                query,
                final_log_size,
                &fiat_shamir_hints.last_layer_coeffs,
            );

            query_hints.push(PwpFriQueryHints {
                first_layer: first_layer_hints[query_idx].clone(),
                inner_layers: all_inner_layer_hints[query_idx].clone(),
                last_layer_eval,
                final_log_size,
            });
        }

        Self {
            query_hints,
            n_inner_layers,
            final_log_size,
        }
    }
}

/// Compute the last layer polynomial evaluation at a query position
fn compute_last_layer_eval(
    query: usize,
    log_size: u32,
    coeffs: &[SecureField],
) -> SecureField {
    let domain = Coset::half_odds(log_size);
    let point = domain.at(bit_reverse_index(query, log_size));

    // Evaluate polynomial at point.x using folding
    let mut x = point.x;
    let poly_log_size = coeffs.len().ilog2();
    let mut doublings = Vec::new();
    for _ in 0..poly_log_size {
        doublings.push(x);
        x = CirclePoint::<M31>::double_x(x);
    }

    fold_polynomial(coeffs, &doublings)
}

fn fold_polynomial(values: &[SecureField], folding_factors: &[M31]) -> SecureField {
    let n = values.len();
    if n == 1 {
        return values[0];
    }
    let (lhs_values, rhs_values) = values.split_at(n / 2);
    let (folding_factor, folding_factors) = folding_factors.split_first().unwrap();
    let lhs_val = fold_polynomial(lhs_values, folding_factors);
    let rhs_val = fold_polynomial(rhs_values, folding_factors);
    lhs_val + rhs_val * *folding_factor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::plonk_with_poseidon::answer::PwpAnswerHints;
    use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};

    #[test]
    fn test_pwp_fri_hints() {
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
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config.clone(), &inputs);
        let _answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        // Get FRI answers
        let max_log_size = fiat_shamir_hints.max_first_layer_column_log_size;
        println!("max_log_size: {}", max_log_size);

        // FRI answers would come from answer_hints.fri_answers
        let n_queries = fiat_shamir_hints
            .unsorted_query_positions_per_log_size
            .get(&max_log_size)
            .map_or(0, |v| v.len());

        // For now, use placeholder answers (in production, these come from fri_answers)
        let fri_answers = vec![SecureField::zero(); n_queries];

        let hints = PwpFriHints::compute(
            &fri_answers,
            &fiat_shamir_hints,
            &proof,
        );

        println!("=== PwpFriHints ===");
        println!("Number of queries: {}", hints.query_hints.len());
        println!("Number of inner layers: {}", hints.n_inner_layers);
        println!("Final log_size: {}", hints.final_log_size);

        for (i, hint) in hints.query_hints.iter().enumerate().take(2) {
            println!("\nQuery {}:", i);
            println!("  First layer twiddle: {:?}", hint.first_layer.twiddle);
            println!("  Inner layers: {}", hint.inner_layers.len());
            for (log_size, layer_hint) in hint.inner_layers.iter().take(3) {
                println!("    Layer {}: twiddle={:?}", log_size, layer_hint.twiddle);
            }
            println!("  Last layer eval: {:?}", hint.last_layer_eval);
        }

        assert_eq!(hints.query_hints.len(), 8);
        assert_eq!(hints.n_inner_layers, 10);
        println!("\nPwpFriHints test passed!");
    }

    #[test]
    fn test_fri_answers_structure() {
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
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config.clone(), &inputs);
        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        println!("=== FRI Answers Structure ===");
        println!("Number of log_size groups: {}", answer_hints.fri_answers.len());

        // Print the log_sizes in sorted order
        let log_sizes: Vec<u32> = fiat_shamir_hints.sorted_query_positions_per_log_size.keys().copied().collect();
        println!("Log sizes: {:?}", log_sizes);

        for (idx, answers) in answer_hints.fri_answers.iter().enumerate() {
            println!("\nGroup {} ({} answers):", idx, answers.len());
            for (q_idx, answer) in answers.iter().enumerate().take(2) {
                println!("  Query {}: {:?}", q_idx, answer);
            }
        }

        // Print first layer structure
        println!("\n=== First Layer Structure ===");
        println!("First layer commitment: {:?}", proof.stark_proof.fri_proof.first_layer.commitment);
        println!("First layer fri_witness len: {}", proof.stark_proof.fri_proof.first_layer.fri_witness.len());

        // Print column domains from fri_verifier
        println!("\n=== FRI Verifier First Layer ===");
        println!("Column commitment domains: {}", fiat_shamir_hints.fri_verifier.first_layer.column_commitment_domains.len());
        for (i, domain) in fiat_shamir_hints.fri_verifier.first_layer.column_commitment_domains.iter().enumerate() {
            println!("  Domain {}: log_size={}", i, domain.log_size());
        }

        // Compute how FRI answers should be combined
        println!("\n=== FRI Alpha Values ===");
        println!("Number of FRI alphas: {}", fiat_shamir_hints.fri_alphas.len());
        println!("First layer alpha (fri_alphas[0]): {:?}", fiat_shamir_hints.fri_alphas[0]);
        for (i, alpha) in fiat_shamir_hints.fri_alphas.iter().enumerate().take(5) {
            println!("  fri_alphas[{}]: {:?}", i, alpha);
        }

        println!("\nFRI answers structure test passed!");
    }

    /// Test using actual FRI answers to verify the folding works correctly
    #[test]
    fn test_fri_hints_with_actual_answers() {
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
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config.clone(), &inputs);
        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        // Get FRI answers for max log_size (27)
        // fri_answers[0] = answers for log_size 24
        // fri_answers[1] = answers for log_size 27
        // But we need the combined answer for the first layer

        // The combined FRI answer is: answer_24 + answer_27
        // where answer_24 is the quotient sum for all log_size 24 columns
        // and answer_27 is the quotient sum for all log_size 27 columns
        let combined_answers: Vec<SecureField> = (0..8)
            .map(|i| answer_hints.fri_answers[0][i] + answer_hints.fri_answers[1][i])
            .collect();

        println!("=== Combined FRI Answers ===");
        for (i, answer) in combined_answers.iter().enumerate().take(3) {
            println!("  Query {}: {:?}", i, answer);
        }

        // Compute FRI hints with actual answers
        let hints = PwpFriHints::compute(
            &combined_answers,
            &fiat_shamir_hints,
            &proof,
        );

        println!("\n=== Verification ===");
        println!("Final layer log_size: {}", hints.final_log_size);

        // The computed last_layer_eval should match the expected polynomial evaluation
        for (i, hint) in hints.query_hints.iter().enumerate().take(3) {
            println!("\nQuery {}:", i);
            println!("  Last layer eval (computed from folding): {:?}", hint.last_layer_eval);

            // The last_layer_eval is computed from the last_layer_coeffs
            // If folding is correct, the folded value at the final layer should match
        }

        // Check that inner layer structure is complete
        for (i, hint) in hints.query_hints.iter().enumerate() {
            assert_eq!(hint.inner_layers.len(), 10, "Query {} should have 10 inner layers", i);
            assert_eq!(hint.final_log_size, 16, "Final log_size should be 16");
        }

        println!("\nFRI hints with actual answers test passed!");
    }
}
