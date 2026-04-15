//! PlonkWithPoseidon Per-Query Part 13: Final Verification
//!
//! This script verifies that the final folded value matches
//! the expected last layer polynomial evaluation.
//!
//! For our FRI config (log_last_layer_degree_bound=9, log_blowup=7):
//! - Final layer log_size = 16
//! - The last layer polynomial evaluation is pre-computed from the coefficients

use crate::script::plonk_with_poseidon::fri_hints::PwpFriQueryHints;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(
    query_idx: usize,
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let _table = TableBar::new_constant(&cs, ())?;

    // Read the final folded value from the last folding layer
    let final_log_size = fri_query_hints.final_log_size;
    let final_value: QM31Bar = ldm_per_query.read(format!("layer_{}", final_log_size))?;

    // The expected last layer polynomial evaluation comes from the hints
    // This was pre-computed from the last_layer_coeffs
    let expected = QM31Bar::new_hint(&cs, fri_query_hints.last_layer_eval)?;

    // Verify they match
    final_value.equalverify(&expected)?;

    // Write a success flag (optional, for debugging)
    ldm_per_query.write(format!("query_{}_verified", query_idx), &final_value)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
