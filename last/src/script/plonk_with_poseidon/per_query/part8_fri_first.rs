//! PlonkWithPoseidon Per-Query Part 8: FRI First Layer
//!
//! This script handles the FRI first layer verification.
//! The first layer combines the STARK answers into a single value
//! that starts the FRI folding process.
//!
//! Input: query_answer (from part7)
//! Output: layer_26 (folded value for inner layer processing)

use crate::script::plonk_with_poseidon::fri_hints::PwpFriQueryHints;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(
    fri_query_hints: &PwpFriQueryHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Read the query answer computed in part7
    let query_answer: QM31Bar = ldm_per_query.read("query_answer")?;

    // Read query position at log_size 27 (max first layer size)
    let query_27: M31Bar = ldm_per_query.read("query_27")?;

    // The first FRI layer folds from log_size 27 to 26
    // We need the first layer alpha
    let first_layer_alpha: QM31Bar = ldm.read("first_layer_alpha")?;

    // Read first layer left/right values from hints
    let first_layer_left = QM31Bar::new_hint(&cs, fri_query_hints.first_layer.left)?;
    let first_layer_right = QM31Bar::new_hint(&cs, fri_query_hints.first_layer.right)?;

    // Determine left/right based on query bit
    let (hi, lo) = split_hi_lo(&query_27, 1)?;
    let query_26 = hi;

    // Swap if needed based on the low bit
    let (left, right) = first_layer_left.conditional_swap(&first_layer_right, &lo);

    // The query answer should match one of the values
    query_answer.equalverify(&left)?;

    // Read twiddle for folding from hints
    let twiddle_27 = M31Bar::new_hint(&cs, fri_query_hints.first_layer.twiddle)?;

    // Fold: t0 = left + right, t1 = (left - right) * twiddle, result = t1 * alpha + t0
    let t0 = &left + &right;
    let t1 = &(&left - &right) * (&table, &twiddle_27);
    let layer_26 = &(&t1 * (&table, &first_layer_alpha)) + &t0;

    // Store for next folding script
    ldm_per_query.write("query_26", &query_26)?;
    ldm_per_query.write("layer_26", &layer_26)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
