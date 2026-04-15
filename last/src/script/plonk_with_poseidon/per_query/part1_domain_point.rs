//! PlonkWithPoseidon Per-Query Part 1: Domain Point Computation
//!
//! This script computes the domain point for a specific query position.
//! Unlike the alt1 approach which uses a precomputed tree for log_sizes 26/28,
//! this version computes domain points directly for log_sizes 24/27.
//!
//! The domain point is needed for:
//! 1. Computing numerators (decommitted values at query positions)
//! 2. FRI folding (twiddles)

use crate::script::plonk_with_poseidon::decommit::{PwpDecommitHints, PwpSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::utils::bit_reverse_index;

/// Generate the domain point computation script for a query
pub fn generate_cs(
    query_idx: usize,
    log_size_24: u32,  // 24 for trace/interaction columns
    log_size_27: u32,  // 27 for composition columns
    decommit_composition_hints: &PwpDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read the query from global LDM
    let query: M31Bar = ldm.read(format!("query_{}", query_idx))?;

    // Compute domain points for both log sizes
    // The commitment domain is CanonicCoset(log_size).circle_domain()
    let commitment_domain_24 = CanonicCoset::new(log_size_24).circle_domain();
    let commitment_domain_27 = CanonicCoset::new(log_size_27).circle_domain();

    // Get the actual query position (bit-reversed)
    let query_val = query.value()?.0 as usize;
    let point_24_val = commitment_domain_24.at(bit_reverse_index(query_val, log_size_24));
    let point_27_val = commitment_domain_27.at(bit_reverse_index(query_val >> 3, log_size_27));

    // Store domain points as hints
    let point_24_x = M31Bar::new_hint(&cs, point_24_val.x)?;
    let point_24_y = M31Bar::new_hint(&cs, point_24_val.y)?;
    let point_27_x = M31Bar::new_hint(&cs, point_27_val.x)?;
    let point_27_y = M31Bar::new_hint(&cs, point_27_val.y)?;

    // Compute y_inv for each point (needed for line coefficient application)
    let point_24_y_inv = if query_val % 2 == 0 {
        M31Bar::new_hint(&cs, point_24_val.y.inverse())?
    } else {
        M31Bar::new_hint(&cs, (-point_24_val.y).inverse())?
    };

    let point_27_y_inv = if (query_val >> 3) % 2 == 0 {
        M31Bar::new_hint(&cs, point_27_val.y.inverse())?
    } else {
        M31Bar::new_hint(&cs, (-point_27_val.y).inverse())?
    };

    // Store domain points in per-query LDM
    ldm_per_query.write("point_24_x", &point_24_x)?;
    ldm_per_query.write("point_24_y", &point_24_y)?;
    ldm_per_query.write("point_24_y_inv", &point_24_y_inv)?;
    ldm_per_query.write("point_27_x", &point_27_x)?;
    ldm_per_query.write("point_27_y", &point_27_y)?;
    ldm_per_query.write("point_27_y_inv", &point_27_y_inv)?;

    // Compute twiddle for FRI folding (inverse of domain point x-coordinate)
    // Twiddle for layer 27 is x_inv of the point at log_size 27
    let twiddle_27 = M31Bar::new_hint(&cs, point_27_val.x.inverse())?;
    ldm_per_query.write("twiddle_27", &twiddle_27)?;

    // Load OODS point from global LDM
    let oods_x: QM31Bar = ldm.read("oods_x")?;
    let oods_y: QM31Bar = ldm.read("oods_y")?;

    let prx = oods_x.first.clone();
    let pry = oods_y.first.clone();
    let pix = oods_x.second.clone();
    let piy = oods_y.second.clone();

    // Compute denominator for OODS at log_size 24
    // denominator = (oods_x - point_x) * piy - (oods_y - point_y) * pix
    let mut denominator_oods_24 = &(&prx - &point_24_x) * (&table, &piy);
    denominator_oods_24 = &denominator_oods_24 - &(&(&pry - &point_24_y) * (&table, &pix));
    let denominator_oods_24 = denominator_oods_24.inverse(&table);
    ldm_per_query.write("denominator_oods_24", &denominator_oods_24)?;

    // Compute denominator for OODS at log_size 27
    let mut denominator_oods_27 = &(&prx - &point_27_x) * (&table, &piy);
    denominator_oods_27 = &denominator_oods_27 - &(&(&pry - &point_27_y) * (&table, &pix));
    let denominator_oods_27 = denominator_oods_27.inverse(&table);
    ldm_per_query.write("denominator_oods_27", &denominator_oods_27)?;

    // Load shifted OODS point
    let oods_shifted_x: QM31Bar = ldm.read("oods_shifted_x")?;
    let oods_shifted_y: QM31Bar = ldm.read("oods_shifted_y")?;

    let prx = oods_shifted_x.first.clone();
    let pry = oods_shifted_y.first.clone();
    let pix = oods_shifted_x.second.clone();
    let piy = oods_shifted_y.second.clone();

    // Compute denominator for shifted OODS at log_size 24
    let mut denominator_oods_24_shifted = &(&prx - &point_24_x) * (&table, &piy);
    denominator_oods_24_shifted = &denominator_oods_24_shifted - &(&(&pry - &point_24_y) * (&table, &pix));
    let denominator_oods_24_shifted = denominator_oods_24_shifted.inverse(&table);
    ldm_per_query.write("denominator_oods_24_shifted", &denominator_oods_24_shifted)?;

    // Verify composition tree decommitment
    let composition_decommitment = PwpSinglePathMerkleProofBar::new_hint(
        &cs,
        decommit_composition_hints.proofs[query_idx].clone(),
    )?;
    let composition_commitment_var: Sha256HashBar = ldm.read("composition_commitment_var")?;

    // Query for log_size 27 is the original query (composition columns)
    // Query for log_size 24 is shifted by 3 bits (preprocessed/trace/interaction columns)
    let query_24 = {
        use recursive_stwo_primitives::bits::split_hi_lo;
        let (hi, lo) = split_hi_lo(&query, 3)?;
        lo.drop();
        hi
    };

    composition_decommitment.verify(&query, log_size_27 as usize, &composition_commitment_var)?;

    // Compute initial numerator for composition columns 0 and 1
    let column_line_coeff_composition_0: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_0")?;
    let numerator_0 = column_line_coeff_composition_0.apply(
        &table,
        &point_27_y,
        &composition_decommitment.columns[0],
    );

    let column_line_coeff_composition_1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_1")?;
    let numerator_1 = column_line_coeff_composition_1.apply(
        &table,
        &point_27_y,
        &composition_decommitment.columns[1],
    );

    let numerator_01 = &numerator_0 + &numerator_1;
    ldm_per_query.write("numerator_composition_01", &numerator_01)?;

    // Store remaining composition values for next script
    ldm_per_query.write("composition_2_val", &composition_decommitment.columns[2])?;
    ldm_per_query.write("composition_3_val", &composition_decommitment.columns[3])?;

    // Store query position for use in subsequent scripts
    // query_24: for log_size 24 trees (preprocessed/trace/interaction) - shifted by 3 bits
    // query_27: for log_size 27 trees (composition) - original query
    ldm_per_query.write("query_24", &query_24)?;
    ldm_per_query.write("query_27", &query)?;

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

    #[test]
    fn test_part1_domain_point() {
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

        // We need to run the global scripts first to set up LDM state
        let mut ldm = LDM::new();

        // Run global scripts to set up state
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
        use crate::script::plonk_with_poseidon::global::line_coeffs::{
            generate_shifted_cs, generate_original_24_cs, generate_composition_cs,
            generate_shifted_interaction_labels, generate_original_logsize_24_labels,
            generate_composition_labels, count_line_coeff_scripts,
        };

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

        println!("Global scripts setup complete");

        // Compute decommit hints
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);

        // Test part1 domain point for query 0
        let mut ldm_per_query = LDM::new();
        let cs = generate_cs(
            0,  // query_idx
            24, // log_size_24
            27, // log_size_27
            &decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();

        let program = Compiler::compile(cs).unwrap();
        println!("part1_domain_point script size: {} bytes", program.script.len());
        println!("part1_domain_point hints: {}", program.hint.len());

        assert!(program.script.len() > 0);
        println!("test_part1_domain_point PASSED!");
    }
}
