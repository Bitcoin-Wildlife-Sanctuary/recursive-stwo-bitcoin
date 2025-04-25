use crate::script::hints::decommit::{LastDecommitHints, LastSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::fields::cm31::CM31Bar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(
    query_idx: usize,
    last_decommit_preprocessed_hints: &LastDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let query_28: M31Bar = ldm.read(format!("query_{}", query_idx))?;
    let query = {
        let (hi, lo) = split_hi_lo(&query_28, 2)?;
        lo.drop();
        hi
    };
    ldm_per_query.write("query_26", &query)?;

    let preprocessed_decommitment = LastSinglePathMerkleProofBar::new_hint(
        &cs,
        last_decommit_preprocessed_hints.proofs[query_idx].clone(),
    )?;
    let preprocessed_commitment_var: Sha256HashBar = ldm.read("preprocessed_commitment_var")?;
    preprocessed_decommitment.verify(&query, 26, &preprocessed_commitment_var)?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_28_y: M31Bar = ldm_per_query.read("point_28_y")?;
    let composition_3_val: M31Bar = ldm_per_query.read("composition_3_val")?;

    let column_line_coeff_composition_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_3")?;
    let numerator_3 =
        column_line_coeff_composition_3.apply(&table, &point_28_y, &composition_3_val);
    let numerator_012: QM31Bar = ldm_per_query.read("numerator_composition_012")?;
    let numerator_composition = &numerator_012 + &numerator_3;
    let denominator_oods_28: CM31Bar = ldm_per_query.read("denominator_oods_28")?;
    let row_28 = &numerator_composition * (&table, &denominator_oods_28);
    ldm_per_query.write("row_28", &row_28)?;
    println!("{:?}", row_28.value()?);

    let point_26_y: M31Bar = ldm_per_query.read("point_26_y")?;

    let column_line_coeff_preprocessed_a_wire: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_a_wire")?;
    let numerator_a_wire = column_line_coeff_preprocessed_a_wire.apply(
        &table,
        &point_26_y,
        &preprocessed_decommitment.columns[0],
    );

    let column_line_coeff_preprocessed_b_wire: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_b_wire")?;
    let numerator_b_wire = column_line_coeff_preprocessed_b_wire.apply(
        &table,
        &point_26_y,
        &preprocessed_decommitment.columns[1],
    );

    let column_line_coeff_preprocessed_c_wire: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_c_wire")?;
    let numerator_c_wire = column_line_coeff_preprocessed_c_wire.apply(
        &table,
        &point_26_y,
        &preprocessed_decommitment.columns[2],
    );

    let column_line_coeff_preprocessed_op1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_preprocessed_op1")?;
    let numerator_op1 = column_line_coeff_preprocessed_op1.apply(
        &table,
        &point_26_y,
        &preprocessed_decommitment.columns[3],
    );

    let mut numerator_a_wire_to_op1 = &numerator_a_wire + &numerator_b_wire;
    numerator_a_wire_to_op1 = &numerator_a_wire_to_op1 + &numerator_c_wire;
    numerator_a_wire_to_op1 = &numerator_a_wire_to_op1 + &numerator_op1;

    ldm_per_query.write(
        "numerator_preprocessed_a_wire_to_op1",
        &numerator_a_wire_to_op1,
    )?;

    ldm_per_query.write("preprocessed_op2", &preprocessed_decommitment.columns[4])?;
    ldm_per_query.write("preprocessed_op3", &preprocessed_decommitment.columns[5])?;
    ldm_per_query.write("preprocessed_op4", &preprocessed_decommitment.columns[6])?;
    ldm_per_query.write("preprocessed_mult_c", &preprocessed_decommitment.columns[7])?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
