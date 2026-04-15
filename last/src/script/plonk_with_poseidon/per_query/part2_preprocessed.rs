//! PlonkWithPoseidon Per-Query Part 2: Preprocessed Decommitment
//!
//! This script verifies the preprocessed tree decommitment and computes
//! numerators for the first batch of preprocessed columns (PLONK preprocessed).
//!
//! Preprocessed columns (50 total):
//! - PLONK preprocessed (10): a_wire, b_wire, c_wire, op, mult_a, mult_b, mult_c, poseidon_wire, mult_poseidon, enforce_c_m31
//! - Poseidon preprocessed (40): is_first_round, is_last_round, is_full_round, round_id, rc0[16], rc1[16], external_idx_1, external_idx_2, is_external_idx_1_nonzero, is_external_idx_2_nonzero

use crate::script::plonk_with_poseidon::decommit::{PwpDecommitHints, PwpSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use num_traits::Zero;
use stwo_prover::core::fields::qm31::QM31;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

/// PLONK preprocessed column labels (10 columns)
const PLONK_PREP_LABELS: [&str; 10] = [
    "plonk_prep_a_wire",
    "plonk_prep_b_wire",
    "plonk_prep_c_wire",
    "plonk_prep_op",
    "plonk_prep_mult_a",
    "plonk_prep_mult_b",
    "plonk_prep_mult_c",
    "plonk_prep_poseidon_wire",
    "plonk_prep_mult_poseidon",
    "plonk_prep_enforce_c_m31",
];

pub fn generate_cs(
    query_idx: usize,
    decommit_preprocessed_hints: &PwpDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read query position
    let query: M31Bar = ldm_per_query.read("query_24")?;

    // Verify preprocessed tree decommitment (50 columns)
    let preprocessed_decommitment = PwpSinglePathMerkleProofBar::new_hint(
        &cs,
        decommit_preprocessed_hints.proofs[query_idx].clone(),
    )?;
    let preprocessed_commitment_var: Sha256HashBar = ldm.read("preprocessed_commitment_var")?;
    preprocessed_decommitment.verify(&query, 24, &preprocessed_commitment_var)?;

    // Get domain point y-coordinate for line coefficient application
    let point_24_y: M31Bar = ldm_per_query.read("point_24_y")?;

    // Process PLONK preprocessed columns (first 10)
    let mut numerator_plonk_prep = QM31Bar::new_constant(&cs, QM31::zero())?;

    for (i, label) in PLONK_PREP_LABELS.iter().enumerate() {
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &preprocessed_decommitment.columns[i]);
        numerator_plonk_prep = &numerator_plonk_prep + &numerator;
    }

    ldm_per_query.write("numerator_plonk_prep", &numerator_plonk_prep)?;

    // Store Poseidon preprocessed column values for next script
    // Columns 10-49 are Poseidon preprocessed (40 columns)
    for i in 10..50 {
        ldm_per_query.write(
            format!("poseidon_prep_val_{}", i - 10),
            &preprocessed_decommitment.columns[i],
        )?;
    }

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::plonk_with_poseidon::decommit::PwpDecommitHints;
    use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
    use recursive_stwo_bitcoin_dsl::compiler::Compiler;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

    fn setup_ldm() -> (LDM, PwpFiatShamirHints<Sha256MerkleChannel>, PlonkWithPoseidonProof<Sha256MerkleHasher>, PcsConfig) {
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

        let mut ldm = LDM::new();

        // Run global scripts
        let cs = crate::script::plonk_with_poseidon::global::part1_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part2_fiat_shamir::generate_cs(&fiat_shamir_hints, &proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part3_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part4_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part5_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part6_fiat_shamir::generate_cs(&proof, config.clone(), &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part7_coset_vanishing::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part10_logup::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part11_point_shift::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();

        // Run line coefficient scripts
        use crate::script::plonk_with_poseidon::global::line_coeffs::*;
        let shifted_labels = generate_shifted_interaction_labels();
        let original_labels = generate_original_logsize_24_labels();
        let composition_labels = generate_composition_labels();
        let (shifted_count, original_count, composition_count, _) = count_line_coeff_scripts();

        for counter in 0..shifted_count {
            let cs = generate_shifted_cs(&mut ldm, counter, &shifted_labels).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }
        for counter in 0..original_count {
            let cs = generate_original_24_cs(&mut ldm, counter, &original_labels, shifted_count).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }
        for counter in 0..composition_count {
            let cs = generate_composition_cs(&mut ldm, counter, &composition_labels).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }

        (ldm, fiat_shamir_hints, proof, config)
    }

    #[test]
    fn test_part2_preprocessed() {
        let (mut ldm, fiat_shamir_hints, proof, _config) = setup_ldm();

        // Run part1 first
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
        let mut ldm_per_query = LDM::new();
        let cs = crate::script::plonk_with_poseidon::per_query::part1_domain_point::generate_cs(
            0, 24, 27,
            &decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let _ = Compiler::compile(cs).unwrap();

        // Now test part2
        let decommit_preprocessed_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 0);
        let cs = generate_cs(
            0,
            &decommit_preprocessed_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();

        let program = Compiler::compile(cs).unwrap();
        println!("part2_preprocessed script size: {} bytes", program.script.len());
        println!("part2_preprocessed hints: {}", program.hint.len());

        assert!(program.script.len() > 0);
        println!("test_part2_preprocessed PASSED!");
    }
}
