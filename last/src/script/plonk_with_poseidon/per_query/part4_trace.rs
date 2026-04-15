//! PlonkWithPoseidon Per-Query Part 4: Trace Decommitment
//!
//! This script verifies the trace tree decommitment and computes
//! numerators for PLONK trace columns (12 columns).
//!
//! Trace columns (60 total):
//! - PLONK trace (12): a_val[4], b_val[4], c_val[4]
//! - Poseidon trace (48): in_state[16], intermediate[16], out_state[16]

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

pub fn generate_cs(
    query_idx: usize,
    decommit_trace_hints: &PwpDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read query position
    let query: M31Bar = ldm_per_query.read("query_24")?;

    // Verify trace tree decommitment (60 columns)
    let trace_decommitment = PwpSinglePathMerkleProofBar::new_hint(
        &cs,
        decommit_trace_hints.proofs[query_idx].clone(),
    )?;
    let trace_commitment_var: Sha256HashBar = ldm.read("trace_commitment_var")?;
    trace_decommitment.verify(&query, 24, &trace_commitment_var)?;

    let point_24_y: M31Bar = ldm_per_query.read("point_24_y")?;

    // Process PLONK trace columns (first 12): a_val[4], b_val[4], c_val[4]
    let mut numerator_plonk_trace = QM31Bar::new_constant(&cs, QM31::zero())?;

    // a_val columns (0-3)
    for i in 0..4 {
        let label = format!("trace_a_val_{}", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &trace_decommitment.columns[i]);
        numerator_plonk_trace = &numerator_plonk_trace + &numerator;
    }

    // b_val columns (4-7)
    for i in 0..4 {
        let label = format!("trace_b_val_{}", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &trace_decommitment.columns[4 + i]);
        numerator_plonk_trace = &numerator_plonk_trace + &numerator;
    }

    // c_val columns (8-11)
    for i in 0..4 {
        let label = format!("trace_c_val_{}", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &trace_decommitment.columns[8 + i]);
        numerator_plonk_trace = &numerator_plonk_trace + &numerator;
    }

    ldm_per_query.write("numerator_plonk_trace", &numerator_plonk_trace)?;

    // Store Poseidon trace column values for next script (columns 12-59)
    for i in 12..60 {
        ldm_per_query.write(
            format!("poseidon_trace_val_{}", i - 12),
            &trace_decommitment.columns[i],
        )?;
    }

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
