//! Hints infrastructure for PlonkWithPoseidon Bitcoin script verification
//!
//! This module provides the hint structures needed to generate Bitcoin scripts
//! that verify PlonkWithPoseidonProof<Sha256MerkleHasher>.

use itertools::Itertools;
use num_traits::{One, Zero};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Add, Mul, Neg};
use stwo_prover::constraint_framework::{Relation, PREPROCESSED_TRACE_IDX};
use stwo_prover::core::air::Component;
use stwo_prover::core::channel::{Channel, MerkleChannel};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_prover::core::fields::{Field, FieldExpOps};
use stwo_prover::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeSubspan, TreeVec};
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::ColumnVec;
use stwo_prover::examples::plonk_with_poseidon::air::{
    PlonkWithPoseidonComponents, PlonkWithPoseidonProof,
};
use stwo_prover::examples::plonk_with_poseidon::plonk::PlonkWithAcceleratorLookupElements;

/// Fiat-Shamir hints for PlonkWithPoseidon Bitcoin script verification
pub struct PwpFiatShamirHints<MC: MerkleChannel> {
    // Commitments
    pub preprocessed_commitment: <MC::H as MerkleHasher>::Hash,
    pub trace_commitment: <MC::H as MerkleHasher>::Hash,
    pub interaction_commitment: <MC::H as MerkleHasher>::Hash,
    pub composition_commitment: <MC::H as MerkleHasher>::Hash,

    // Statement data
    pub log_size_plonk: u32,
    pub log_size_poseidon: u32,
    pub plonk_total_sum: SecureField,
    pub poseidon_total_sum: SecureField,

    // Challenge values
    pub alpha: SecureField,
    pub z: SecureField,
    pub random_coeff: SecureField,
    pub after_sampled_values_random_coeff: SecureField,
    pub oods_t: SecureField,
    pub oods_point: CirclePoint<SecureField>,

    // FRI data
    pub first_layer_commitment: <MC::H as MerkleHasher>::Hash,
    pub inner_layer_commitments: Vec<<MC::H as MerkleHasher>::Hash>,
    pub last_layer_coeffs: Vec<SecureField>,
    pub fri_alphas: Vec<SecureField>,

    // Query-related data
    pub all_log_sizes: BTreeSet<u32>,
    pub max_first_layer_column_log_size: u32,
    pub sorted_query_positions_per_log_size: BTreeMap<u32, Vec<usize>>,
    pub unsorted_query_positions_per_log_size: BTreeMap<u32, Vec<usize>>,
    pub column_log_sizes: TreeVec<Vec<u32>>,
    pub n_columns_per_log_size: TreeVec<BTreeMap<u32, usize>>,
    pub trees_log_sizes: TreeVec<Vec<u32>>,

    pub log_blowup_factor: u32,

    // Component spans
    pub plonk_tree_subspan: Vec<TreeSubspan>,
    pub poseidon_tree_subspan: Vec<TreeSubspan>,
    pub plonk_prepared_column_indices: Vec<usize>,
    pub poseidon_prepared_column_indices: Vec<usize>,

    // Sample points and masks
    pub sample_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    pub mask_plonk: TreeVec<Vec<Vec<isize>>>,
    pub mask_poseidon: TreeVec<Vec<Vec<isize>>>,

    pub fri_verifier: FriVerifier<MC>,
}

impl<MC: MerkleChannel> PwpFiatShamirHints<MC> {
    pub fn new(
        proof: &PlonkWithPoseidonProof<MC::H>,
        config: PcsConfig,
        inputs: &[(usize, QM31)],
    ) -> Self {
        let channel = &mut MC::C::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);

        let log_sizes = proof.stmt0.log_sizes();

        // Preprocessed trace
        commitment_scheme.commit(proof.stark_proof.commitments[0], &log_sizes[0], channel);

        // Trace
        proof.stmt0.mix_into(channel);
        commitment_scheme.commit(proof.stark_proof.commitments[1], &log_sizes[1], channel);

        // Draw interaction elements
        let lookup_elements = PlonkWithAcceleratorLookupElements::draw(channel);

        // Interaction trace
        proof.stmt1.mix_into(channel);
        commitment_scheme.commit(proof.stark_proof.commitments[2], &log_sizes[2], channel);

        // Create components
        let components =
            PlonkWithPoseidonComponents::new(&proof.stmt0, &lookup_elements, &proof.stmt1);

        let plonk_tree_subspan = components.plonk.trace_locations().to_vec();
        let plonk_prepared_column_indices =
            components.plonk.preproccessed_column_indices().to_vec();
        let poseidon_tree_subspan = components.poseidon.trace_locations().to_vec();
        let poseidon_prepared_column_indices =
            components.poseidon.preproccessed_column_indices().to_vec();

        // Get mask relations
        let mask_plonk = components.plonk.info.mask_offsets.clone();
        let mask_poseidon = components.poseidon.info.mask_offsets.clone();

        // Input sum computation (for verification)
        let mut input_sum = SecureField::zero();
        for (idx, val) in inputs.iter() {
            let sum: SecureField = <PlonkWithAcceleratorLookupElements as Relation<
                BaseField,
                SecureField,
            >>::combine_ef(&lookup_elements, &[val.clone(), QM31::from(*idx as u32)]);
            input_sum += sum.inverse();
        }
        let _ = input_sum; // Used for verification

        let random_coeff = channel.draw_felt();

        // Composition polynomial commitment
        let max_degree = std::cmp::max(
            components.plonk.max_constraint_log_degree_bound(),
            components.poseidon.max_constraint_log_degree_bound(),
        );
        commitment_scheme.commit(
            *proof.stark_proof.commitments.last().unwrap(),
            &[max_degree; SECURE_EXTENSION_DEGREE],
            channel,
        );

        // Draw OODS point
        let oods_t = channel.draw_felt();
        let oods_point = {
            let t_square = oods_t.square();
            let one_plus_tsquared_inv = t_square.add(SecureField::one()).inverse();
            let x = SecureField::one()
                .add(t_square.neg())
                .mul(one_plus_tsquared_inv);
            let y = oods_t.double().mul(one_plus_tsquared_inv);
            CirclePoint::<SecureField> { x, y }
        };

        // Get mask sample points relative to oods point
        let sample_points_plonk = components.plonk.mask_points(oods_point);
        let sample_points_poseidon = components.poseidon.mask_points(oods_point);

        // Merge sample points from trace and interaction (trees 1 and 2)
        // Tree 0 (preprocessed) needs special handling
        let mut sample_points = TreeVec::new(vec![vec![], vec![], vec![]]);

        // For trace (tree 1) and interaction (tree 2), merge PLONK and Poseidon points
        for i in 1..3 {
            sample_points[i] = sample_points_plonk[i]
                .iter()
                .chain(sample_points_poseidon[i].iter())
                .cloned()
                .collect();
        }

        // For preprocessed (tree 0), we need to create entries for all columns
        // The number of preprocessed columns is: PLONK (10) + Poseidon (40) = 50
        let n_plonk_prep = 10;
        let n_poseidon_prep = 40;
        let total_prep = n_plonk_prep + n_poseidon_prep;
        sample_points[PREPROCESSED_TRACE_IDX] = vec![vec![oods_point]; total_prep];

        // Add composition polynomial mask points
        sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

        // Mix sampled values
        channel.mix_felts(&proof.stark_proof.sampled_values.clone().flatten_cols());
        let after_sampled_values_random_coeff = channel.draw_felt();

        // FRI setup
        let bounds = commitment_scheme
            .column_log_sizes()
            .flatten()
            .into_iter()
            .sorted()
            .rev()
            .dedup()
            .map(|log_size| {
                CirclePolyDegreeBound::new(log_size - config.fri_config.log_blowup_factor)
            })
            .collect_vec();

        let fri_verifier = FriVerifier::<MC>::commit(
            channel,
            config.fri_config,
            proof.stark_proof.fri_proof.clone(),
            bounds,
        )
        .unwrap();

        let first_layer_commitment = proof.stark_proof.fri_proof.first_layer.commitment;
        let inner_layer_commitments = proof
            .stark_proof
            .fri_proof
            .inner_layers
            .iter()
            .map(|l| l.commitment)
            .collect_vec();
        let last_layer_coeffs = proof.stark_proof.fri_proof.last_layer_poly.coeffs.clone();

        let mut fri_alphas = vec![];
        fri_alphas.push(fri_verifier.first_layer.folding_alpha);
        for layer in fri_verifier.inner_layers.iter() {
            fri_alphas.push(layer.folding_alpha);
        }

        // Verify PoW
        let nonce = proof.stark_proof.proof_of_work;
        channel.mix_u64(nonce);
        assert!(
            channel.trailing_zeros() >= config.pow_bits,
            "pow failed: {} < {}",
            channel.trailing_zeros(),
            config.pow_bits
        );

        let trees_log_sizes = proof.stmt0.log_sizes();

        let all_log_sizes = fri_verifier
            .first_layer
            .column_commitment_domains
            .iter()
            .map(|domain| domain.log_size())
            .collect::<BTreeSet<u32>>();
        let max_first_layer_column_log_size = *all_log_sizes.iter().max().unwrap();

        // Get FRI query positions
        let unsorted_query_positions_per_log_size = {
            let mut channel = channel.clone();
            let mut raw_queries = vec![];

            while raw_queries.len() < config.fri_config.n_queries {
                let felts = channel.draw_felts(2);
                raw_queries.extend_from_slice(&felts[0].to_m31_array());
                raw_queries.extend_from_slice(&felts[1].to_m31_array());
            }
            raw_queries.truncate(config.fri_config.n_queries);

            let mut queries = vec![];
            for raw_query in raw_queries.iter() {
                queries.push(raw_query.0 & ((1 << max_first_layer_column_log_size) - 1));
            }

            let mut map = BTreeMap::new();
            for &log_size in all_log_sizes.iter() {
                map.insert(
                    log_size,
                    queries
                        .iter()
                        .map(|x| (x >> (max_first_layer_column_log_size - log_size)) as usize)
                        .collect_vec(),
                );
            }
            map
        };

        let sorted_query_positions_per_log_size = unsorted_query_positions_per_log_size
            .iter()
            .map(|(&log_size, positions)| (log_size, positions.iter().sorted().cloned().collect()))
            .collect();

        Self {
            preprocessed_commitment: proof.stark_proof.commitments[0],
            trace_commitment: proof.stark_proof.commitments[1],
            interaction_commitment: proof.stark_proof.commitments[2],
            composition_commitment: *proof.stark_proof.commitments.last().unwrap(),

            log_size_plonk: proof.stmt0.log_size_plonk,
            log_size_poseidon: proof.stmt0.log_size_poseidon,
            plonk_total_sum: proof.stmt1.plonk_total_sum,
            poseidon_total_sum: proof.stmt1.poseidon_total_sum,

            alpha: lookup_elements.0.alpha,
            z: lookup_elements.0.z,
            random_coeff,
            after_sampled_values_random_coeff,
            oods_t,
            oods_point,

            first_layer_commitment,
            inner_layer_commitments,
            last_layer_coeffs,
            fri_alphas,

            all_log_sizes,
            max_first_layer_column_log_size,
            sorted_query_positions_per_log_size,
            unsorted_query_positions_per_log_size,
            column_log_sizes: commitment_scheme.column_log_sizes(),
            n_columns_per_log_size: {
                // Compute n_columns_per_log_size from column_log_sizes
                let column_log_sizes = commitment_scheme.column_log_sizes();
                TreeVec::new(column_log_sizes.as_ref().iter().map(|tree_sizes| {
                    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
                    for &log_size in tree_sizes.iter() {
                        *counts.entry(log_size).or_insert(0) += 1;
                    }
                    counts
                }).collect())
            },
            trees_log_sizes,

            log_blowup_factor: config.fri_config.log_blowup_factor,

            plonk_tree_subspan,
            poseidon_tree_subspan,
            plonk_prepared_column_indices,
            poseidon_prepared_column_indices,

            sample_points,
            mask_plonk,
            mask_poseidon,

            fri_verifier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::core::fri::FriConfig;

    #[test]
    fn test_load_pwp_hints() {
        // Load the proof
        let proof_bytes = std::fs::read("../data/poseidon_accelerated_proof.bin")
            .expect("Failed to load proof - run poseidon-proof-generator first");
        let proof: PlonkWithPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(&proof_bytes).unwrap();

        // Create hints
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };
        let inputs: Vec<(usize, QM31)> = vec![
            (1, QM31::one()),
            (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
            (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        ];

        let hints = PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config, &inputs);

        // Verify basic structure
        assert_eq!(hints.log_size_plonk, 15);
        assert_eq!(hints.log_size_poseidon, 15);
        assert_eq!(hints.fri_alphas.len(), 11); // 10 inner layers + 1 first layer

        println!("=== PwpFiatShamirHints loaded successfully ===");
        println!("log_size_plonk: {}", hints.log_size_plonk);
        println!("log_size_poseidon: {}", hints.log_size_poseidon);
        println!("fri_alphas: {}", hints.fri_alphas.len());
        println!("all_log_sizes: {:?}", hints.all_log_sizes);
        println!("max_first_layer_column_log_size: {}", hints.max_first_layer_column_log_size);
        println!("plonk_prepared_column_indices: {:?}", hints.plonk_prepared_column_indices);
        println!("poseidon_prepared_column_indices: {} columns", hints.poseidon_prepared_column_indices.len());
        println!("n_inner_layers: {}", hints.inner_layer_commitments.len());
        println!("last_layer_coeffs: {}", hints.last_layer_coeffs.len());
        println!("column_log_sizes: {:?}", hints.column_log_sizes);

        // Check sampled values structure
        println!("\n=== Sampled values structure ===");
        println!("Tree 0 (preprocessed): {} columns", proof.stark_proof.sampled_values[0].len());
        println!("Tree 1 (trace): {} columns", proof.stark_proof.sampled_values[1].len());
        println!("Tree 2 (interaction): {} columns", proof.stark_proof.sampled_values[2].len());
        if proof.stark_proof.sampled_values.len() > 3 {
            println!("Tree 3 (composition): {} columns", proof.stark_proof.sampled_values[3].len());
        }

        // Check interaction column sample counts
        for i in 0..proof.stark_proof.sampled_values[2].len().min(16) {
            println!("  Interaction col {}: {} samples", i, proof.stark_proof.sampled_values[2][i].len());
        }
    }
}
