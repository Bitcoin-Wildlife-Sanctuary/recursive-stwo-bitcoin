use crate::script::hints::decommit::{LastDecommitHints, LastSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::cm31::CM31Bar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(
    query_idx: usize,
    last_decommit_interaction_hints: &LastDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_26_y: M31Bar = ldm_per_query.read("point_26_y")?;
    let query: M31Bar = ldm_per_query.read("query_26")?;

    let interaction_decommitment = LastSinglePathMerkleProofBar::new_hint(
        &cs,
        last_decommit_interaction_hints.proofs[query_idx].clone(),
    )?;
    let interaction_commitment_var: Sha256HashBar = ldm.read("interaction_commitment_var")?;
    interaction_decommitment.verify(&query, 26, &interaction_commitment_var)?;

    ldm_per_query.write("interaction_0", &interaction_decommitment.columns[0])?;
    ldm_per_query.write("interaction_1", &interaction_decommitment.columns[1])?;
    ldm_per_query.write("interaction_2", &interaction_decommitment.columns[2])?;
    ldm_per_query.write("interaction_3", &interaction_decommitment.columns[3])?;

    let column_line_coeff_interaction_0: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_0")?;
    let numerator_interaction_0 = column_line_coeff_interaction_0.apply(
        &table,
        &point_26_y,
        &interaction_decommitment.columns[0],
    );

    let column_line_coeff_interaction_1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_1")?;
    let numerator_interaction_1 = column_line_coeff_interaction_1.apply(
        &table,
        &point_26_y,
        &interaction_decommitment.columns[1],
    );

    let column_line_coeff_interaction_2: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_2")?;
    let numerator_interaction_2 = column_line_coeff_interaction_2.apply(
        &table,
        &point_26_y,
        &interaction_decommitment.columns[2],
    );

    let column_line_coeff_interaction_3: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_interaction_3")?;
    let numerator_interaction_3 = column_line_coeff_interaction_3.apply(
        &table,
        &point_26_y,
        &interaction_decommitment.columns[3],
    );

    let mut numerator_interaction = &numerator_interaction_0 + &numerator_interaction_1;
    numerator_interaction = &numerator_interaction + &numerator_interaction_2;
    numerator_interaction = &numerator_interaction + &numerator_interaction_3;

    let numerator_preprocessed: QM31Bar = ldm_per_query.read("numerator_preprocessed")?;
    let numerator_trace: QM31Bar = ldm_per_query.read("numerator_trace")?;

    let mut numerator = &numerator_preprocessed + &numerator_trace;
    numerator = &numerator + &numerator_interaction;

    let denominator_oods_26: CM31Bar = ldm_per_query.read("denominator_oods_26")?;
    let row_preprocessed_to_interaction = &numerator * (&table, &denominator_oods_26);
    ldm_per_query.write(
        "row_preprocessed_to_interaction",
        &row_preprocessed_to_interaction,
    )?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
