//! PlonkWithPoseidon Per-Query Part 6: Interaction Decommitment and Numerators
//!
//! This script verifies the interaction tree decommitment and computes
//! numerators for all interaction columns (16 columns).
//!
//! Interaction columns (16 total):
//! - PLONK interaction (8): plonk_interaction_0..7
//! - Poseidon interaction (8): poseidon_interaction_0..7
//!
//! Note: Columns 4-7 for both PLONK and Poseidon have shifted samples,
//! which are handled separately using the shifted OODS point.

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
    decommit_interaction_hints: &PwpDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read query position
    let query: M31Bar = ldm_per_query.read("query_24")?;

    // Verify interaction tree decommitment (16 columns)
    let interaction_decommitment = PwpSinglePathMerkleProofBar::new_hint(
        &cs,
        decommit_interaction_hints.proofs[query_idx].clone(),
    )?;
    let interaction_commitment_var: Sha256HashBar = ldm.read("interaction_commitment_var")?;
    interaction_decommitment.verify(&query, 24, &interaction_commitment_var)?;

    let point_24_y: M31Bar = ldm_per_query.read("point_24_y")?;

    let mut numerator_interaction = QM31Bar::new_constant(&cs, QM31::zero())?;

    // Process PLONK interaction columns 0-3 (original point)
    for i in 0..4 {
        let label = format!("plonk_interaction_{}", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &interaction_decommitment.columns[i]);
        numerator_interaction = &numerator_interaction + &numerator;
    }

    // Process PLONK interaction columns 4-7 (shifted point)
    // These use the shifted OODS point for line coefficients
    for i in 4..8 {
        let label = format!("plonk_interaction_{}_shifted", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &interaction_decommitment.columns[i]);
        numerator_interaction = &numerator_interaction + &numerator;
    }

    // Process Poseidon interaction columns 0-3 (original point)
    for i in 0..4 {
        let label = format!("poseidon_interaction_{}", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &interaction_decommitment.columns[8 + i]);
        numerator_interaction = &numerator_interaction + &numerator;
    }

    // Process Poseidon interaction columns 4-7 (shifted point)
    for i in 4..8 {
        let label = format!("poseidon_interaction_{}_shifted", i);
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &interaction_decommitment.columns[8 + i]);
        numerator_interaction = &numerator_interaction + &numerator;
    }

    ldm_per_query.write("numerator_interaction", &numerator_interaction)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
