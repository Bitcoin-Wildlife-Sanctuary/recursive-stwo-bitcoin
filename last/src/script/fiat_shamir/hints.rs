use num_traits::Zero;
use std::collections::{BTreeMap, BTreeSet};
use stwo_prover::constraint_framework::{Relation, TraceLocationAllocator};
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::fri::FriVerifier;
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

        todo!()
    }
}

#[cfg(test)]
mod test {
    use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
    use circle_plonk_dsl_last_answer::data_structures::{LastDecommitHints, LastDecommitInput};
    use circle_plonk_dsl_last_fiat_shamir::LastFiatShamirInput;
    use circle_plonk_dsl_last_folding::data_structures::merkle_proofs::{
        LastFirstLayerHints, LastInnerLayersHints,
    };
    use num_traits::One;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
        Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
    };
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
    use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

    #[test]
    fn test_last_fiat_shamir_hints() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../../data/hybrid_hash.bin")).unwrap();

        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        let fiat_shamir_hints = FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
            &proof,
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        );
        let fiat_shamir_input = LastFiatShamirInput::from_proof(&proof, &fiat_shamir_hints);
        let decommit_hints = LastDecommitHints::from_proof(&fiat_shamir_hints, &proof);
        let decommit_input = LastDecommitInput::from_hints(&decommit_hints);
        let fri_answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
        let first_layer_hints =
            LastFirstLayerHints::compute(&fiat_shamir_hints, &fri_answer_hints, &proof);
        let inner_layers_hints = LastInnerLayersHints::compute(
            &first_layer_hints.folded_evals_by_column,
            &fiat_shamir_hints,
            &proof,
        );

        let mut inputs = vec![];
        let add_input = |inputs: &mut Vec<(usize, QM31)>, input: QM31| {
            let idx = inputs.len() + 1;
            inputs.push((idx, input))
        };
        let pack_queries = |slice: &[usize]| {
            let mut slice = slice.to_vec();
            assert!(slice.len() <= 4);
            slice.resize(4, 0);
            QM31::from_u32_unchecked(
                slice[0] as u32,
                slice[1] as u32,
                slice[2] as u32,
                slice[3] as u32,
            )
        };

        add_input(&mut inputs, QM31::one());
        add_input(&mut inputs, QM31::from_u32_unchecked(0, 1, 0, 0));
        add_input(&mut inputs, QM31::from_u32_unchecked(0, 0, 1, 0));
        add_input(&mut inputs, fiat_shamir_input.t);
        add_input(
            &mut inputs,
            QM31::from_m31_array(std::array::from_fn(|i| {
                fiat_shamir_input.sampled_values_hash.0[i]
            })),
        );
        add_input(
            &mut inputs,
            QM31::from_m31_array(std::array::from_fn(|i| {
                fiat_shamir_input.sampled_values_hash.0[i + 4]
            })),
        );
        add_input(&mut inputs, fiat_shamir_input.plonk_total_sum);
        add_input(&mut inputs, fiat_shamir_input.poseidon_total_sum);
        add_input(&mut inputs, fiat_shamir_hints.z);
        add_input(&mut inputs, fiat_shamir_hints.alpha);
        add_input(&mut inputs, fiat_shamir_input.random_coeff);
        add_input(
            &mut inputs,
            fiat_shamir_input.after_sampled_values_random_coeff,
        );
        add_input(
            &mut inputs,
            pack_queries(&fiat_shamir_input.queries_at_max_first_layer_column_log_size[0..4]),
        );
        add_input(
            &mut inputs,
            pack_queries(&fiat_shamir_input.queries_at_max_first_layer_column_log_size[4..8]),
        );
        for fri_alpha in fiat_shamir_input.fri_alphas.iter() {
            add_input(&mut inputs, *fri_alpha);
        }
        for proof in decommit_input
            .precomputed_proofs
            .iter()
            .chain(decommit_input.trace_proofs.iter())
            .chain(decommit_input.interaction_proofs.iter())
            .chain(decommit_input.composition_proofs.iter())
        {
            for (_, column) in proof.packed_columns.iter() {
                for elem in column.iter() {
                    add_input(&mut inputs, *elem);
                }
            }
        }
        for proof in first_layer_hints.merkle_proofs.iter() {
            for (_, elem) in proof.self_columns.iter() {
                add_input(&mut inputs, *elem);
            }
            for (_, elem) in proof.siblings_columns.iter() {
                add_input(&mut inputs, *elem);
            }
        }
        for (_, proofs) in inner_layers_hints.merkle_proofs.iter() {
            for proof in proofs.iter() {
                for (_, elem) in proof.self_columns.iter() {
                    add_input(&mut inputs, *elem);
                }
                for (_, elem) in proof.siblings_columns.iter() {
                    add_input(&mut inputs, *elem);
                }
            }
        }

        let proof_last: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../../data/bitcoin_proof.bin")).unwrap();
    }
}
