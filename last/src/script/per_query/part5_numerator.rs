use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
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

    let trace_b_val_2: M31Bar = ldm_per_query.read("trace_b_val_2")?;
    let column_line_coeff_trace_b_val_2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_b_val_2")?;
    let numerator_b_val_2 =
        column_line_coeff_trace_b_val_2.apply(&table, &point_26_y, &trace_b_val_2);

    let trace_b_val_3: M31Bar = ldm_per_query.read("trace_b_val_3")?;
    let column_line_coeff_trace_b_val_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_b_val_3")?;
    let numerator_b_val_3 =
        column_line_coeff_trace_b_val_3.apply(&table, &point_26_y, &trace_b_val_3);

    let trace_c_val_0: M31Bar = ldm_per_query.read("trace_c_val_0")?;
    let column_line_coeff_trace_c_val_0: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_c_val_0")?;
    let numerator_c_val_0 =
        column_line_coeff_trace_c_val_0.apply(&table, &point_26_y, &trace_c_val_0);

    let trace_c_val_1: M31Bar = ldm_per_query.read("trace_c_val_1")?;
    let column_line_coeff_trace_c_val_1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_c_val_1")?;
    let numerator_c_val_1 =
        column_line_coeff_trace_c_val_1.apply(&table, &point_26_y, &trace_c_val_1);

    let trace_c_val_2: M31Bar = ldm_per_query.read("trace_c_val_2")?;
    let column_line_coeff_trace_c_val_2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_c_val_2")?;
    let numerator_c_val_2 =
        column_line_coeff_trace_c_val_2.apply(&table, &point_26_y, &trace_c_val_2);

    let trace_c_val_3: M31Bar = ldm_per_query.read("trace_c_val_3")?;
    let column_line_coeff_trace_c_val_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_trace_c_val_3")?;
    let numerator_c_val_3 =
        column_line_coeff_trace_c_val_3.apply(&table, &point_26_y, &trace_c_val_3);

    let numerator_a_val_0_to_b_val_1: QM31Bar =
        ldm_per_query.read("numerator_trace_a_val_0_to_b_val_1")?;
    let mut numerator_trace = &numerator_a_val_0_to_b_val_1 + &numerator_b_val_2;
    numerator_trace = &numerator_trace + &numerator_b_val_3;
    numerator_trace = &numerator_trace + &numerator_c_val_0;
    numerator_trace = &numerator_trace + &numerator_c_val_1;
    numerator_trace = &numerator_trace + &numerator_c_val_2;
    numerator_trace = &numerator_trace + &numerator_c_val_3;

    ldm_per_query.write("numerator_trace", &numerator_trace)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
