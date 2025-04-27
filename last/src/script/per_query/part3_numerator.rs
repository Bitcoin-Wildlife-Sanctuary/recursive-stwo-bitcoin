use crate::script::hints::decommit::{LastDecommitHints, LastSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(
    query_idx: usize,
    last_decommit_trace_hints: &LastDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let query: M31Bar = ldm_per_query.read("query_26")?;

    let trace_decommitment = LastSinglePathMerkleProofBar::new_hint(
        &cs,
        last_decommit_trace_hints.proofs[query_idx].clone(),
    )?;
    let trace_commitment_var: Sha256HashBar = ldm.read("trace_commitment_var")?;
    trace_decommitment.verify(&query, 26, &trace_commitment_var)?;

    ldm_per_query.write("trace_a_val_0", &trace_decommitment.columns[0])?;
    ldm_per_query.write("trace_a_val_1", &trace_decommitment.columns[1])?;
    ldm_per_query.write("trace_a_val_2", &trace_decommitment.columns[2])?;
    ldm_per_query.write("trace_a_val_3", &trace_decommitment.columns[3])?;
    ldm_per_query.write("trace_b_val_0", &trace_decommitment.columns[4])?;
    ldm_per_query.write("trace_b_val_1", &trace_decommitment.columns[5])?;
    ldm_per_query.write("trace_b_val_2", &trace_decommitment.columns[6])?;
    ldm_per_query.write("trace_b_val_3", &trace_decommitment.columns[7])?;
    ldm_per_query.write("trace_c_val_0", &trace_decommitment.columns[8])?;
    ldm_per_query.write("trace_c_val_1", &trace_decommitment.columns[9])?;
    ldm_per_query.write("trace_c_val_2", &trace_decommitment.columns[10])?;
    ldm_per_query.write("trace_c_val_3", &trace_decommitment.columns[11])?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_26_y: M31Bar = ldm_per_query.read("point_26_y")?;

    let preprocessed_op1: M31Bar = ldm_per_query.read("preprocessed_op1")?;
    let column_line_coeff_preprocessed_op1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_op1")?;
    let numerator_op1 =
        column_line_coeff_preprocessed_op1.apply(&table, &point_26_y, &preprocessed_op1);

    let preprocessed_op2: M31Bar = ldm_per_query.read("preprocessed_op2")?;
    let column_line_coeff_preprocessed_op2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_op2")?;
    let numerator_op2 =
        column_line_coeff_preprocessed_op2.apply(&table, &point_26_y, &preprocessed_op2);

    let preprocessed_op3: M31Bar = ldm_per_query.read("preprocessed_op3")?;
    let column_line_coeff_preprocessed_op3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_op3")?;
    let numerator_op3 =
        column_line_coeff_preprocessed_op3.apply(&table, &point_26_y, &preprocessed_op3);

    let preprocessed_op4: M31Bar = ldm_per_query.read("preprocessed_op4")?;
    let column_line_coeff_preprocessed_op4: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_op4")?;
    let numerator_op4 =
        column_line_coeff_preprocessed_op4.apply(&table, &point_26_y, &preprocessed_op4);

    let preprocessed_mult_c: M31Bar = ldm_per_query.read("preprocessed_mult_c")?;
    let column_line_coeff_preprocessed_mult_c: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_mult_c")?;
    let numerator_mult_c =
        column_line_coeff_preprocessed_mult_c.apply(&table, &point_26_y, &preprocessed_mult_c);

    let numerator_a_wire_to_c_wire: QM31Bar =
        ldm_per_query.read("numerator_preprocessed_a_wire_to_c_wire")?;
    let mut numerator_preprocessed = &numerator_a_wire_to_c_wire + &numerator_op1;
    numerator_preprocessed = &numerator_preprocessed + &numerator_op2;
    numerator_preprocessed = &numerator_preprocessed + &numerator_op3;
    numerator_preprocessed = &numerator_preprocessed + &numerator_op4;
    numerator_preprocessed = &numerator_preprocessed + &numerator_mult_c;

    ldm_per_query.write("numerator_preprocessed", &numerator_preprocessed)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
