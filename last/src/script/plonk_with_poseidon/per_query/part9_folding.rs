//! PlonkWithPoseidon Per-Query Part 9-11: FRI Inner Layer Folding
//!
//! These scripts handle FRI folding through the inner layers.
//! With 10 inner layers (log_size 26 -> 16):
//! - Part 9: layers 26->22 (4 layers, alpha indices 1-4)
//! - Part 10: layers 22->18 (4 layers, alpha indices 5-8)
//! - Part 11: layers 18->16 (2 layers, alpha indices 9-10)

use crate::script::plonk_with_poseidon::fri_hints::PwpFriQueryHints;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

/// Generate folding script for a range of layers
/// `start_layer` is the starting log_size (e.g., 26)
/// `end_layer` is the ending log_size (e.g., 22)
/// `alpha_offset` is the starting index for inner_layer_alpha (1-indexed from first_layer)
pub fn generate_folding_cs(
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
    start_layer: u32,
    end_layer: u32,
    alpha_offset: usize,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read starting state
    let mut query: M31Bar = ldm_per_query.read(format!("query_{}", start_layer))?;
    let mut current_layer: QM31Bar = ldm_per_query.read(format!("layer_{}", start_layer))?;

    // Fold through each layer
    for layer_idx in 0..(start_layer - end_layer) as usize {
        let log_size = start_layer - layer_idx as u32;
        let alpha_idx = alpha_offset + layer_idx;

        // Get hints for this layer
        let layer_hints = fri_query_hints
            .inner_layers
            .get(&log_size)
            .expect(&format!("Missing inner layer hints for log_size {}", log_size));

        // Load self and sibling values from hints
        let self_value = QM31Bar::new_hint(&cs, layer_hints.self_value)?;
        let sibling_value = QM31Bar::new_hint(&cs, layer_hints.sibling_value)?;

        // Verify current layer matches expected self value
        current_layer.equalverify(&self_value)?;

        // Extract bit and update query
        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        // Swap based on query bit to get (left, right)
        let (left, right) = self_value.conditional_swap(&sibling_value, &lo);

        // Read twiddle from hints
        let twiddle = M31Bar::new_hint(&cs, layer_hints.twiddle)?;

        // Read alpha from global LDM
        let alpha: QM31Bar = ldm.read(format!("inner_layer_alpha_{}", alpha_idx))?;

        // Fold: t0 = left + right, t1 = (left - right) * twiddle, result = t1 * alpha + t0
        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &twiddle);
        current_layer = &(&t1 * (&table, &alpha)) + &t0;
    }

    // Store final state
    ldm_per_query.write(format!("query_{}", end_layer), &query)?;
    ldm_per_query.write(format!("layer_{}", end_layer), &current_layer)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}

/// Part 9: Fold from layer 26 to 22 (4 layers)
/// Uses inner_layer_alpha_0 through inner_layer_alpha_3
pub fn generate_part9_cs(
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    generate_folding_cs(fri_query_hints, ldm, ldm_per_query, 26, 22, 0)
}

/// Part 10: Fold from layer 22 to 18 (4 layers)
/// Uses inner_layer_alpha_4 through inner_layer_alpha_7
pub fn generate_part10_cs(
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    generate_folding_cs(fri_query_hints, ldm, ldm_per_query, 22, 18, 4)
}

/// Part 11: Fold from layer 18 to 16 (2 layers)
/// Uses inner_layer_alpha_8 through inner_layer_alpha_9
pub fn generate_part11_cs(
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    generate_folding_cs(fri_query_hints, ldm, ldm_per_query, 18, 16, 8)
}
