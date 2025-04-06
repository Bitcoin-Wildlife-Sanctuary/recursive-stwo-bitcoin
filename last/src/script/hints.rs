use itertools::Itertools;
use num_traits::{One, Zero};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Add, Mul, Neg};
use stwo_prover::constraint_framework::{Relation, TraceLocationAllocator};
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
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;
use stwo_prover::examples::plonk_without_poseidon::plonk::{
    PlonkWithoutAcceleratorComponent, PlonkWithoutAcceleratorEval,
    PlonkWithoutAcceleratorLookupElements,
};

pub struct LastFiatShamirHints<MC: MerkleChannel> {
    pub preprocessed_commitment: <MC::H as MerkleHasher>::Hash,
    pub trace_commitment: <MC::H as MerkleHasher>::Hash,
    pub interaction_commitment: <MC::H as MerkleHasher>::Hash,
    pub composition_commitment: <MC::H as MerkleHasher>::Hash,

    pub log_size_plonk: u32,
    pub plonk_total_sum: SecureField,

    pub alpha: SecureField,
    pub z: SecureField,
    pub random_coeff: SecureField,
    pub after_sampled_values_random_coeff: SecureField,
    pub oods_t: SecureField,
    pub oods_point: CirclePoint<SecureField>,
    pub first_layer_commitment: <MC::H as MerkleHasher>::Hash,
    pub inner_layer_commitments: Vec<<MC::H as MerkleHasher>::Hash>,
    pub last_layer_coeffs: Vec<SecureField>,
    pub fri_alphas: Vec<SecureField>,

    pub all_log_sizes: BTreeSet<u32>,
    pub max_first_layer_column_log_size: u32,
    pub sorted_query_positions_per_log_size: BTreeMap<u32, Vec<usize>>,
    pub unsorted_query_positions_per_log_size: BTreeMap<u32, Vec<usize>>,
    pub column_log_sizes: TreeVec<Vec<u32>>,
    pub n_columns_per_log_size: TreeVec<BTreeMap<u32, usize>>,
    pub trees_log_sizes: TreeVec<Vec<u32>>,

    pub log_blowup_factor: u32,

    pub plonk_tree_subspan: Vec<TreeSubspan>,

    pub plonk_prepared_column_indices: Vec<usize>,

    pub sample_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    pub mask_plonk: TreeVec<Vec<Vec<isize>>>,

    pub fri_verifier: FriVerifier<MC>,
}

impl<MC: MerkleChannel> LastFiatShamirHints<MC> {
    pub fn new(
        proof: &PlonkWithoutPoseidonProof<MC::H>,
        config: PcsConfig,
        inputs: &[(usize, QM31)],
    ) -> LastFiatShamirHints<MC> {
        let channel = &mut MC::C::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);

        let log_sizes = proof.stmt0.log_sizes();

        // Preprocessed trace.
        commitment_scheme.commit(proof.stark_proof.commitments[0], &log_sizes[0], channel);

        // Trace.
        proof.stmt0.mix_into(channel);
        commitment_scheme.commit(proof.stark_proof.commitments[1], &log_sizes[1], channel);

        // Draw interaction elements.
        let lookup_elements = PlonkWithoutAcceleratorLookupElements::draw(channel);

        // Interaction trace.
        proof.stmt1.mix_into(channel);
        commitment_scheme.commit(proof.stark_proof.commitments[2], &log_sizes[2], channel);

        let component = PlonkWithoutAcceleratorComponent::new(
            &mut TraceLocationAllocator::default(),
            PlonkWithoutAcceleratorEval {
                log_n_rows: proof.stmt0.log_size_plonk,
                lookup_elements: lookup_elements.clone(),
                total_sum: proof.stmt1.plonk_total_sum,
            },
            proof.stmt1.plonk_total_sum,
        );

        let plonk_tree_subspan = component.trace_locations().to_vec();
        let plonk_prepared_column_indices = component.preproccessed_column_indices().to_vec();

        // Get the mask relations
        let mask_plonk = component.info.mask_offsets.clone();

        let mut input_sum = SecureField::zero();
        for (idx, val) in inputs.iter() {
            let sum: SecureField = <PlonkWithoutAcceleratorLookupElements as Relation<
                BaseField,
                SecureField,
            >>::combine_ef(
                &lookup_elements, &[val.clone(), QM31::from(*idx as u32)]
            );
            input_sum += sum.inverse();
        }

        let total_sum = proof.stmt1.plonk_total_sum + input_sum;
        assert_eq!(total_sum, SecureField::zero());

        let random_coeff = channel.draw_felt();

        // Read composition polynomial commitment.
        commitment_scheme.commit(
            *proof.stark_proof.commitments.last().unwrap(),
            &[component.max_constraint_log_degree_bound(); SECURE_EXTENSION_DEGREE],
            channel,
        );

        // Draw OODS point.
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

        // Get mask sample points relative to oods point.
        let mut sample_points = component.mask_points(oods_point);
        // Add the composition polynomial mask points.
        sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

        channel.mix_felts(&proof.stark_proof.sampled_values.clone().flatten_cols());
        let after_sampled_values_random_coeff = channel.draw_felt();

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

        // FRI commitment phase on OODS quotients.
        let mut fri_verifier = FriVerifier::<MC>::commit(
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
        assert_eq!(
            proof.stark_proof.fri_proof.last_layer_poly.len(),
            1 << config.fri_config.log_last_layer_degree_bound
        );
        assert_eq!(config.fri_config.log_last_layer_degree_bound, 0);
        let last_layer_evaluation = proof.stark_proof.fri_proof.last_layer_poly.coeffs.clone();

        let mut fri_alphas = vec![];
        fri_alphas.push(fri_verifier.first_layer.folding_alpha);
        for layer in fri_verifier.inner_layers.iter() {
            fri_alphas.push(layer.folding_alpha);
        }
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

        // Get FRI query positions.
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
        let sorted_query_positions_per_log_size = fri_verifier.sample_query_positions(channel);

        let column_log_sizes = commitment_scheme
            .trees
            .as_ref()
            .map(|tree| tree.column_log_sizes.clone());
        let n_columns_per_log_size = commitment_scheme
            .trees
            .as_ref()
            .map(|tree| tree.n_columns_per_log_size.clone());

        LastFiatShamirHints {
            preprocessed_commitment: proof.stark_proof.commitments[0],
            trace_commitment: proof.stark_proof.commitments[1],
            interaction_commitment: proof.stark_proof.commitments[2],
            composition_commitment: proof.stark_proof.commitments[3],
            log_size_plonk: proof.stmt0.log_size_plonk,
            plonk_total_sum: proof.stmt1.plonk_total_sum,
            alpha: lookup_elements.0.alpha,
            z: lookup_elements.0.z,
            random_coeff,
            after_sampled_values_random_coeff,
            oods_t,
            oods_point,
            first_layer_commitment,
            inner_layer_commitments,
            last_layer_coeffs: last_layer_evaluation,
            fri_alphas,
            all_log_sizes,
            max_first_layer_column_log_size,
            sorted_query_positions_per_log_size,
            unsorted_query_positions_per_log_size,
            column_log_sizes,
            n_columns_per_log_size,
            trees_log_sizes,
            log_blowup_factor: config.fri_config.log_blowup_factor,
            plonk_tree_subspan,
            plonk_prepared_column_indices,
            sample_points,
            mask_plonk,
            fri_verifier,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::script::hints::LastFiatShamirHints;
    use recursive_stwo_delegation::script::compute_delegation_inputs;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleHasher;
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
    use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

    #[test]
    fn test_last_fiat_shamir_hints() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../data/hybrid_hash.bin")).unwrap();
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        let inputs = compute_delegation_inputs(&proof, config);

        let proof_last: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../data/bitcoin_proof.bin")).unwrap();
        let config_last = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(0, 9, 8),
        };

        let _ = LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);
    }
}
