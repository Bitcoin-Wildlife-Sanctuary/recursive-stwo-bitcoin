use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::cm31::CM31Bar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(ldm: &mut LDM, ldm_per_query: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_26_y: M31Bar = ldm_per_query.read("point_26_y")?;

    let interaction_0: M31Bar = ldm_per_query.read("interaction_0")?;
    let column_line_coeff_interaction_prev_0: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_prev_0")?;
    let numerator_interaction_prev_0 =
        column_line_coeff_interaction_prev_0.apply(&table, &point_26_y, &interaction_0);

    let interaction_1: M31Bar = ldm_per_query.read("interaction_1")?;
    let column_line_coeff_interaction_prev_1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_prev_1")?;
    let numerator_interaction_prev_1 =
        column_line_coeff_interaction_prev_1.apply(&table, &point_26_y, &interaction_1);

    let interaction_2: M31Bar = ldm_per_query.read("interaction_2")?;
    let column_line_coeff_interaction_prev_2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_prev_2")?;
    let numerator_interaction_prev_2 =
        column_line_coeff_interaction_prev_2.apply(&table, &point_26_y, &interaction_2);

    let interaction_3: M31Bar = ldm_per_query.read("interaction_3")?;
    let column_line_coeff_interaction_prev_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_prev_3")?;
    let numerator_interaction_prev_3 =
        column_line_coeff_interaction_prev_3.apply(&table, &point_26_y, &interaction_3);

    let mut numerator_interaction_prev =
        &numerator_interaction_prev_0 + &numerator_interaction_prev_1;
    numerator_interaction_prev = &numerator_interaction_prev + &numerator_interaction_prev_2;
    numerator_interaction_prev = &numerator_interaction_prev + &numerator_interaction_prev_3;

    let denominator_oods_26_shifted: CM31Bar = ldm_per_query.read("denominator_oods_26_shifted")?;
    let row_interaction_prev = &numerator_interaction_prev * (&table, &denominator_oods_26_shifted);

    let row_preprocessed_to_interaction: QM31Bar =
        ldm_per_query.read("row_preprocessed_to_interaction")?;
    let row_26 = &row_interaction_prev + &row_preprocessed_to_interaction;
    ldm_per_query.write("row_26", &row_26)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
