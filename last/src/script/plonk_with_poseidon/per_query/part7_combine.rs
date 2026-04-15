//! PlonkWithPoseidon Per-Query Part 7: Combine Numerators
//!
//! This script combines all numerators computed in previous scripts
//! and computes the final row values for both log_sizes (24 and 27).
//!
//! Row value = numerator * denominator_inverse

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::cm31::CM31Bar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Load all numerator components
    let numerator_preprocessed: QM31Bar = ldm_per_query.read("numerator_preprocessed")?;
    let numerator_trace: QM31Bar = ldm_per_query.read("numerator_trace")?;
    let numerator_interaction: QM31Bar = ldm_per_query.read("numerator_interaction")?;

    // Combine numerators for log_size 24 columns
    let mut numerator_24 = &numerator_preprocessed + &numerator_trace;
    numerator_24 = &numerator_24 + &numerator_interaction;

    // Compute row value for log_size 24
    let denominator_oods_24: CM31Bar = ldm_per_query.read("denominator_oods_24")?;
    let row_24 = &numerator_24 * (&table, &denominator_oods_24);
    ldm_per_query.write("row_24", &row_24)?;

    // Complete composition numerator (columns 2 and 3)
    let numerator_composition_01: QM31Bar = ldm_per_query.read("numerator_composition_01")?;
    let composition_2_val: M31Bar = ldm_per_query.read("composition_2_val")?;
    let composition_3_val: M31Bar = ldm_per_query.read("composition_3_val")?;
    let point_27_y: M31Bar = ldm_per_query.read("point_27_y")?;

    let column_line_coeff_composition_2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_2")?;
    let numerator_2 = column_line_coeff_composition_2.apply(&table, &point_27_y, &composition_2_val);

    let column_line_coeff_composition_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_3")?;
    let numerator_3 = column_line_coeff_composition_3.apply(&table, &point_27_y, &composition_3_val);

    let numerator_composition = &(&numerator_composition_01 + &numerator_2) + &numerator_3;

    // Compute row value for log_size 27 (composition)
    let denominator_oods_27: CM31Bar = ldm_per_query.read("denominator_oods_27")?;
    let row_27 = &numerator_composition * (&table, &denominator_oods_27);
    ldm_per_query.write("row_27", &row_27)?;

    // Combine row values into final answer for this query
    // The FRI answer is row_24 + row_27
    let query_answer = &row_24 + &row_27;
    ldm_per_query.write("query_answer", &query_answer)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
