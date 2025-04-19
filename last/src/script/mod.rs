pub mod hints;
pub mod twiddles;

pub mod global;
pub mod per_query;

pub mod part_last;

#[cfg(test)]
mod test {
    use crate::script::global::part12_line_coeffs::generate_oods_shifted_logsize_26_labels;
    use crate::script::global::part13_line_coeffs::{
        generate_oods_original_logsize_26_labels, generate_oods_original_logsize_28_labels,
    };
    use crate::script::global::{
        part10_logup, part11_point_shift, part12_line_coeffs, part13_line_coeffs,
        part14_line_coeffs, part1_fiat_shamir, part2_input_sum, part3_fiat_shamir,
        part4_composition, part5_composition, part6_composition, part7_coset_vanishing,
        part8_coset_vanishing, part9_coset_vanishing,
    };
    use crate::script::hints::LastFiatShamirHints;
    use crate::script::part_last;
    use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
    use num_traits::{One, Zero};
    use recursive_stwo_bitcoin_dsl::ldm::LDM;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_delegation::folding::{DelegatedFirstLayerHints, DelegatedInnerLayersHints};
    use recursive_stwo_delegation::script::{compute_delegation_inputs, compute_input_labels};
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
        Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
    };
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
    use stwo_prover::examples::plonk_without_poseidon::air::{
        verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
    };

    fn get_delegated_ldm(
        proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
        config: PcsConfig,
    ) -> LDM {
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

        let _ = recursive_stwo_delegation::script::part1::generate_cs(
            &fiat_shamir_hints,
            &proof,
            config,
            &mut ldm_delegated,
        )
        .unwrap();
        let _ = recursive_stwo_delegation::script::part2::generate_cs(
            &fiat_shamir_hints,
            &proof,
            &first_layer_hints,
            &mut ldm_delegated,
        )
        .unwrap();
        let _ = recursive_stwo_delegation::script::part3::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated,
        )
        .unwrap();
        let _ = recursive_stwo_delegation::script::part4::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated,
        )
        .unwrap();
        let _ = recursive_stwo_delegation::script::part5::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated,
        )
        .unwrap();

        ldm_delegated
    }

    #[test]
    fn test_last_verifier() {
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

        verify_plonk_without_poseidon::<Sha256MerkleChannel>(
            proof_last.clone(),
            config_last,
            &inputs,
        )
        .unwrap();

        let mut ldm = get_delegated_ldm(&proof, config);
        let last_fiat_shamir_hints =
            LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);

        let mut script_total_len = 0;

        let cs = part1_fiat_shamir::generate_cs(&proof_last, &mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let input_labels = compute_input_labels();
        for counter in 0..39 {
            let cs = part2_input_sum::generate_cs(&mut ldm, counter, &input_labels).unwrap();
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        assert_eq!(
            ldm.debug_read::<QM31>("input_acc_sum_39").unwrap() + proof_last.stmt1.plonk_total_sum,
            QM31::zero()
        );

        let cs = part3_fiat_shamir::generate_cs(
            &last_fiat_shamir_hints,
            &proof_last,
            config_last,
            &mut ldm,
        )
        .unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part4_composition::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part5_composition::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part6_composition::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part7_coset_vanishing::generate_cs(&proof_last, &mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part10_logup::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part11_point_shift::generate_cs(&proof_last, &mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let oods_shifted_logsize_26_labels = generate_oods_shifted_logsize_26_labels();
        for counter in 0..2 {
            let cs =
                part12_line_coeffs::generate_cs(&mut ldm, counter, &oods_shifted_logsize_26_labels)
                    .unwrap();
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        let oods_original_logsize_26_labels = generate_oods_original_logsize_26_labels();
        for counter in 0..12 {
            let cs = part13_line_coeffs::generate_cs(
                &mut ldm,
                counter,
                &oods_original_logsize_26_labels,
            )
            .unwrap();
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        let oods_original_logsize_28_labels = generate_oods_original_logsize_28_labels();
        for counter in 0..2 {
            let cs = part14_line_coeffs::generate_cs(
                &mut ldm,
                counter,
                &oods_original_logsize_28_labels,
            )
            .unwrap();
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        let cs = part_last::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(cs, script! {}).unwrap();

        println!("current total script length: {}", script_total_len);
    }
}
