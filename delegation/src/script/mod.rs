use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
use circle_plonk_dsl_last_answer::data_structures::{LastDecommitHints, LastDecommitInput};
use circle_plonk_dsl_last_fiat_shamir::LastFiatShamirInput;
use circle_plonk_dsl_last_folding::data_structures::merkle_proofs::{
    LastFirstLayerHints, LastInnerLayersHints,
};
use num_traits::One;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub mod part1;

pub mod part2;

pub mod part3;

pub mod part4;

pub mod part5;

pub fn compute_delegation_inputs(
    proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    config: PcsConfig,
) -> Vec<(usize, QM31)> {
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

    inputs
}

pub fn compute_input_labels() -> Vec<String> {
    let mut v = vec![];
    v.push("delegated_oods_t".to_string());
    v.push("delegated_sampled_value_hash_0".to_string());
    v.push("delegated_sampled_value_hash_1".to_string());
    v.push("delegated_plonk_total_sum".to_string());
    v.push("delegated_poseidon_total_sum".to_string());
    v.push("delegated_z".to_string());
    v.push("delegated_alpha".to_string());
    v.push("delegated_random_coeff".to_string());
    v.push("delegated_after_sampled_values_random_coeff".to_string());
    v.push("delegated_queries_felt_1".to_string());
    v.push("delegated_queries_felt_2".to_string());

    v.push("delegated_first_layer_folding_alpha".to_string());
    for i in 0..10 {
        v.push(format!("delegated_inner_layers_folding_alpha_{}", i));
    }
    for i in 0..16 {
        v.push(format!("delegated_decommit_preprocessed_input_{}", i));
    }
    for i in 0..16 {
        v.push(format!("delegated_decommit_trace_input_{}", i));
    }
    for i in 0..16 {
        v.push(format!("delegated_decommit_interaction_input_{}", i));
    }
    for i in 0..8 {
        v.push(format!("delegated_decommit_composition_input_{}", i));
    }
    for i in 0..32 {
        v.push(format!("delegated_first_layer_input_{}", i));
    }
    for i in 0..10 {
        for j in 0..16 {
            v.push(format!("delegated_inner_layers_input_{}_{}", i, j));
        }
    }
    v
}

#[cfg(test)]
mod test {
    use crate::folding::{DelegatedFirstLayerHints, DelegatedInnerLayersHints};
    use crate::script::{compute_delegation_inputs, part1, part2, part3, part4, part5};
    use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
    use itertools::Itertools;
    use num_traits::One;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::ldm::LDM;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_primitives::fields::qm31::QM31Bar;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
        Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
    };
    use stwo_prover::examples::plonk_with_poseidon::air::{
        verify_plonk_with_poseidon, PlonkWithPoseidonProof,
    };

    #[test]
    fn test_delegated() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../data/hybrid_hash.bin")).unwrap();
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        verify_plonk_with_poseidon::<Sha256Poseidon31MerkleChannel>(
            proof.clone(),
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        )
        .unwrap();

        let fiat_shamir_hints = FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
            &proof,
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        );
        let fri_answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
        let first_layer_hints =
            DelegatedFirstLayerHints::compute(&fiat_shamir_hints, &fri_answer_hints, &proof);
        let inner_layers_hints = DelegatedInnerLayersHints::compute(
            &first_layer_hints.folded_evals_by_column,
            &fiat_shamir_hints,
            &proof,
        );

        let mut ldm_delegated = LDM::new();

        let cs =
            part1::generate_cs(&fiat_shamir_hints, &proof, config, &mut ldm_delegated).unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part2::generate_cs(
            &fiat_shamir_hints,
            &proof,
            &first_layer_hints,
            &mut ldm_delegated,
        )
        .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part3::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part4::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part5::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();
    }

    #[test]
    fn test_input_elements() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../data/hybrid_hash.bin")).unwrap();
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        verify_plonk_with_poseidon::<Sha256Poseidon31MerkleChannel>(
            proof.clone(),
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        )
        .unwrap();

        let fiat_shamir_hints = FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
            &proof,
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        );
        let fri_answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
        let first_layer_hints =
            DelegatedFirstLayerHints::compute(&fiat_shamir_hints, &fri_answer_hints, &proof);
        let inner_layers_hints = DelegatedInnerLayersHints::compute(
            &first_layer_hints.folded_evals_by_column,
            &fiat_shamir_hints,
            &proof,
        );

        let mut ldm_delegated = LDM::new();

        let cs =
            part1::generate_cs(&fiat_shamir_hints, &proof, config, &mut ldm_delegated).unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let _ = part2::generate_cs(
            &fiat_shamir_hints,
            &proof,
            &first_layer_hints,
            &mut ldm_delegated,
        )
        .unwrap();
        let _ = part3::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();
        let _ = part4::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();
        let _ = part5::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated)
            .unwrap();

        let cs = BitcoinSystemRef::new_ref();
        ldm_delegated.init(&cs).unwrap();

        let mut input_elements = vec![];
        let oods_t: QM31Bar = ldm_delegated.read("delegated_oods_t").unwrap();
        input_elements.push(oods_t.value().unwrap());
        let sampled_value_hash_0: QM31Bar = ldm_delegated
            .read("delegated_sampled_value_hash_0")
            .unwrap();
        input_elements.push(sampled_value_hash_0.value().unwrap());
        let sampled_value_hash_1: QM31Bar = ldm_delegated
            .read("delegated_sampled_value_hash_1")
            .unwrap();
        input_elements.push(sampled_value_hash_1.value().unwrap());
        let plonk_total_sum: QM31Bar = ldm_delegated.read("delegated_plonk_total_sum").unwrap();
        input_elements.push(plonk_total_sum.value().unwrap());
        let poseidon_total_sum: QM31Bar =
            ldm_delegated.read("delegated_poseidon_total_sum").unwrap();
        input_elements.push(poseidon_total_sum.value().unwrap());
        let z: QM31Bar = ldm_delegated.read("delegated_z").unwrap();
        input_elements.push(z.value().unwrap());
        let alpha: QM31Bar = ldm_delegated.read("delegated_alpha").unwrap();
        input_elements.push(alpha.value().unwrap());
        let random_coeff: QM31Bar = ldm_delegated.read("delegated_random_coeff").unwrap();
        input_elements.push(random_coeff.value().unwrap());
        let after_sampled_values_random_coeff: QM31Bar = ldm_delegated
            .read("delegated_after_sampled_values_random_coeff")
            .unwrap();
        input_elements.push(after_sampled_values_random_coeff.value().unwrap());
        let queries_felt_1: QM31Bar = ldm_delegated.read("delegated_queries_felt_1").unwrap();
        input_elements.push(queries_felt_1.value().unwrap());
        let queries_felt_2: QM31Bar = ldm_delegated.read("delegated_queries_felt_2").unwrap();
        input_elements.push(queries_felt_2.value().unwrap());
        let first_layer_folding_alpha: QM31Bar = ldm_delegated
            .read("delegated_first_layer_folding_alpha")
            .unwrap();
        input_elements.push(first_layer_folding_alpha.value().unwrap());
        for i in 0..proof.stark_proof.fri_proof.inner_layers.len() {
            let inner_layer_folding_alpha: QM31Bar = ldm_delegated
                .read(format!("delegated_inner_layers_folding_alpha_{}", i))
                .unwrap();
            input_elements.push(inner_layer_folding_alpha.value().unwrap());
        }
        for i in 0..16 {
            let decommit_item: QM31Bar = ldm_delegated
                .read(format!("delegated_decommit_preprocessed_input_{}", i))
                .unwrap();
            input_elements.push(decommit_item.value().unwrap());
        }
        for i in 0..16 {
            let decommit_item: QM31Bar = ldm_delegated
                .read(format!("delegated_decommit_trace_input_{}", i))
                .unwrap();
            input_elements.push(decommit_item.value().unwrap());
        }
        for i in 0..16 {
            let decommit_item: QM31Bar = ldm_delegated
                .read(format!("delegated_decommit_interaction_input_{}", i))
                .unwrap();
            input_elements.push(decommit_item.value().unwrap());
        }
        for i in 0..8 {
            let decommit_item: QM31Bar = ldm_delegated
                .read(format!("delegated_decommit_composition_input_{}", i))
                .unwrap();
            input_elements.push(decommit_item.value().unwrap());
        }
        for i in 0..32 {
            let fri_item: QM31Bar = ldm_delegated
                .read(format!("delegated_first_layer_input_{}", i))
                .unwrap();
            input_elements.push(fri_item.value().unwrap());
        }
        for i in 0..10 {
            for j in 0..16 {
                let fri_item: QM31Bar = ldm_delegated
                    .read(format!("delegated_inner_layers_input_{}_{}", i, j))
                    .unwrap();
                input_elements.push(fri_item.value().unwrap());
            }
        }

        let expected_elements = compute_delegation_inputs(&proof, config)
            .iter()
            .map(|x| x.1)
            .collect_vec();
        assert_eq!(input_elements.len(), expected_elements.len());
        assert_eq!(input_elements, expected_elements);
    }
}
