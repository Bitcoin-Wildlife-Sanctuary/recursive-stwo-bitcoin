pub mod part1;

pub mod part2;

pub mod part3;

pub mod part4;

pub mod part5;

#[cfg(test)]
mod test {
    use crate::folding::{DelegatedFirstLayerHints, DelegatedInnerLayersHints};
    use crate::script::{part1, part2, part3, part4, part5};
    use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
    use num_traits::One;
    use recursive_stwo_bitcoin_dsl::ldm::LDM;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
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
            bincode::deserialize(include_bytes!("../data/hybrid_hash.bin")).unwrap();
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

        let mut ldm_delegated_1 = LDM::new();
        let mut ldm_delegated_2 = LDM::new();

        let cs =
            part1::generate_cs(&fiat_shamir_hints, &proof, config, &mut ldm_delegated_1).unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated_1.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part2::generate_cs(
            &fiat_shamir_hints,
            &proof,
            &first_layer_hints,
            &mut ldm_delegated_1,
        )
        .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated_1.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part3::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated_1,
            &mut ldm_delegated_2,
        )
        .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated_1.hash_var.as_ref().unwrap().value.clone() }
                { ldm_delegated_2.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part4::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated_1,
            &mut ldm_delegated_2,
        )
        .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated_1.hash_var.as_ref().unwrap().value.clone() }
                { ldm_delegated_2.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = part5::generate_cs(
            &fiat_shamir_hints,
            &inner_layers_hints,
            &mut ldm_delegated_1,
            &mut ldm_delegated_2,
        )
        .unwrap();
        test_program(
            cs,
            script! {
                { ldm_delegated_1.hash_var.as_ref().unwrap().value.clone() }
                { ldm_delegated_2.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();
    }
}
