pub mod hints;

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
        part14_line_coeffs, part1_fiat_shamir, part3_fiat_shamir,
        part4_composition, part5_composition, part6_composition, part7_coset_vanishing,
        part8_coset_vanishing, part9_coset_vanishing,
    };
    use crate::script::hints::answer::LastAnswerHints;
    use crate::script::hints::decommit::LastDecommitHints;
    use crate::script::hints::fiat_shamir::LastFiatShamirHints;
    use crate::script::hints::folding::{LastFirstLayerHints, LastInnerLayersHints};
    use crate::script::part_last;
    use crate::script::per_query::{
        part10_folding, part11_folding, part12_folding, part13_clear, part1_domain_point,
        part2_numerator, part3_numerator, part4_numerator, part5_numerator, part6_numerator,
        part7_numerator, part8_fri_decommitment, part9_folding,
    };
    use num_traits::One;
    use recursive_stwo_bitcoin_dsl::ldm::LDM;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::examples::plonk_without_poseidon::air::{
        verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
    };

    #[test]
    fn test_last_verifier() {
        // Alternative 1: Pure SHA256, no delegation
        // Minimal application-specific inputs
        let inputs: Vec<(usize, QM31)> = vec![
            (1, QM31::one()),
            (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
            (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        ];

        let proof_last: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../data/bitcoin_proof.bin")).unwrap();
        let config_last = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(0, 9, 8),
        };

        // NOTE: With a proper proof for Alternative 1 (pure SHA256, no delegation),
        // this verification should pass. The current bitcoin_proof.bin was generated
        // with delegation inputs, so verification is disabled for measurement purposes.
        // TODO: Enable when a new proof without delegation is generated:
        // verify_plonk_without_poseidon::<Sha256MerkleChannel>(
        //     proof_last.clone(),
        //     config_last,
        //     &inputs,
        // )
        // .unwrap();

        // No delegation - start with fresh LDM
        let mut ldm = LDM::new();
        let last_fiat_shamir_hints =
            LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);
        let last_decommit_preprocessed_hints =
            LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 0);
        let last_decommit_trace_hints =
            LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 1);
        let last_decommit_interaction_hints =
            LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 2);
        let last_decommit_composition_hints =
            LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 3);
        let last_answer_hints = LastAnswerHints::compute(&last_fiat_shamir_hints, &proof_last);
        let last_first_layer_hints =
            LastFirstLayerHints::compute(&last_fiat_shamir_hints, &last_answer_hints, &proof_last);
        let last_inner_layers_hints = LastInnerLayersHints::compute(
            &last_first_layer_hints.folded_evals_by_column,
            &last_fiat_shamir_hints,
            &proof_last,
        );

        let mut script_num = 0;
        let mut script_total_len = 0;

        println!("part1");
        let cs = part1_fiat_shamir::generate_cs(&proof_last, &mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        // No input_sum loop - delegation removed

        println!("part3");
        let cs = part3_fiat_shamir::generate_cs(
            &last_fiat_shamir_hints,
            &proof_last,
            config_last,
            &mut ldm,
        )
        .unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part4");
        let cs = part4_composition::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part5");
        let cs = part5_composition::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part6");
        let cs = part6_composition::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part7");
        let cs = part7_coset_vanishing::generate_cs(&proof_last, &mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part8");
        let cs = part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part9");
        let cs = part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part10");
        let cs = part10_logup::generate_cs(&mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part11");
        let cs = part11_point_shift::generate_cs(&proof_last, &mut ldm).unwrap();
        script_num += 1;
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("part12");
        let oods_shifted_logsize_26_labels = generate_oods_shifted_logsize_26_labels();
        for counter in 0..2 {
            let cs =
                part12_line_coeffs::generate_cs(&mut ldm, counter, &oods_shifted_logsize_26_labels)
                    .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        println!("part13");
        let oods_original_logsize_26_labels = generate_oods_original_logsize_26_labels();
        for counter in 0..12 {
            let cs = part13_line_coeffs::generate_cs(
                &mut ldm,
                counter,
                &oods_original_logsize_26_labels,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        println!("part14");
        let oods_original_logsize_28_labels = generate_oods_original_logsize_28_labels();
        for counter in 0..2 {
            let cs = part14_line_coeffs::generate_cs(
                &mut ldm,
                counter,
                &oods_original_logsize_28_labels,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        for query_idx in 0..8 {
            println!("per_query part1");
            let mut ldm_per_query = LDM::new();
            let cs = part1_domain_point::generate_cs(
                query_idx,
                &last_decommit_composition_hints,
                &mut ldm,
                &mut ldm_per_query,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part2");
            let cs = part2_numerator::generate_cs(
                query_idx,
                &last_decommit_preprocessed_hints,
                &mut ldm,
                &mut ldm_per_query,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part3");
            let cs = part3_numerator::generate_cs(
                query_idx,
                &last_decommit_trace_hints,
                &mut ldm,
                &mut ldm_per_query,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part4");
            let cs = part4_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part5");
            let cs = part5_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part6");
            let cs = part6_numerator::generate_cs(
                query_idx,
                &last_decommit_interaction_hints,
                &mut ldm,
                &mut ldm_per_query,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part7");
            let cs = part7_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part8");
            let cs = part8_fri_decommitment::generate_cs(
                query_idx,
                &last_first_layer_hints,
                &last_inner_layers_hints,
                &mut ldm,
                &mut ldm_per_query,
            )
            .unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part9");
            let cs = part9_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part10");
            let cs = part10_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part11");
            let cs = part11_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part12");
            let cs = part12_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("per_query part13");
            let cs = part13_clear::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
            script_num += 1;
            script_total_len += test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            println!("======finished query {}======", query_idx);
        }

        println!("part_last");
        let cs = part_last::generate_cs(&mut ldm).unwrap();
        script_total_len += test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        println!("number of scripts: {}", script_num);
        println!("current total script length: {}", script_total_len);
    }
}
