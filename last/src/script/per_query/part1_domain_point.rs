use crate::script::hints::decommit::{LastDecommitHints, LastSinglePathMerkleProofBar};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::circle::precomputed::{PrecomputedTree, PrecomputedTreeResultVar};
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;
use std::path::PathBuf;

pub fn generate_cs(
    query_idx: usize,
    last_decommit_composition_hints: &LastDecommitHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let upper_tree = PrecomputedTree::build_upper_tree(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/precomputed_tree.bin"),
    )?;
    let query: M31Bar = ldm.read(format!("query_{}", query_idx))?;
    let precomputed_result = PrecomputedTreeResultVar::fetch_and_verify(&upper_tree, &query)?;

    ldm_per_query.write("point_28_x", &precomputed_result.point_28.x)?;
    ldm_per_query.write("point_28_y", &precomputed_result.point_28.y)?;
    ldm_per_query.write("point_28_y_inv", &precomputed_result.point_28_y_inv)?;

    ldm_per_query.write("point_26_x", &precomputed_result.point_26.x)?;
    ldm_per_query.write("point_26_y", &precomputed_result.point_26.y)?;
    ldm_per_query.write("point_26_y_inv", &precomputed_result.point_26_y_inv)?;

    //  236482303 1284792366
    println!(
        "for this query {} {}",
        query.value()?.0 >> 1,
        precomputed_result.twiddles[&27].value()?
    );

    let oods_x: QM31Bar = ldm.read("oods_x")?;
    let oods_y: QM31Bar = ldm.read("oods_y")?;

    let prx = oods_x.first;
    let pry = oods_y.first;
    let pix = oods_x.second;
    let piy = oods_y.second;

    let composition_decommitment = LastSinglePathMerkleProofBar::new_hint(
        &cs,
        last_decommit_composition_hints.proofs[query_idx].clone(),
    )?;
    let composition_commitment_var: Sha256HashBar = ldm.read("composition_commitment_var")?;
    composition_decommitment.verify(&query, 28, &composition_commitment_var)?;

    let table = TableBar::new_constant(&cs, ())?;
    let mut denominator_oods = &(&prx - &precomputed_result.point_28.x) * (&table, &piy);
    denominator_oods =
        &denominator_oods - &(&(&pry - &precomputed_result.point_28.y) * (&table, &pix));
    denominator_oods = denominator_oods.inverse(&table);
    ldm_per_query.write("denominator_oods_28", &denominator_oods)?;

    let mut denominator_oods = &(&prx - &precomputed_result.point_26.x) * (&table, &piy);
    denominator_oods =
        &denominator_oods - &(&(&pry - &precomputed_result.point_26.y) * (&table, &pix));
    denominator_oods = denominator_oods.inverse(&table);
    ldm_per_query.write("denominator_oods_26", &denominator_oods)?;

    let oods_shifted_x: QM31Bar = ldm.read("oods_shifted_x")?;
    let oods_shifted_y: QM31Bar = ldm.read("oods_shifted_y")?;

    let prx = oods_shifted_x.first;
    let pry = oods_shifted_y.first;
    let pix = oods_shifted_x.second;
    let piy = oods_shifted_y.second;

    let mut denominator_oods_shifted = &(&prx - &precomputed_result.point_26.x) * (&table, &piy);
    denominator_oods_shifted =
        &denominator_oods_shifted - &(&(&pry - &precomputed_result.point_26.y) * (&table, &pix));
    denominator_oods_shifted = denominator_oods_shifted.inverse(&table);
    ldm_per_query.write("denominator_oods_26_shifted", &denominator_oods_shifted)?;

    let column_line_coeff_composition_0: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_0")?;
    let numerator_0 = column_line_coeff_composition_0.apply(
        &table,
        &precomputed_result.point_28.y,
        &composition_decommitment.columns[0],
    );
    let column_line_coeff_composition_1: ColumnLineCoeffBar =
        ldm.read("column_line_coeff_composition_1")?;
    let numerator_1 = column_line_coeff_composition_1.apply(
        &table,
        &precomputed_result.point_28.y,
        &composition_decommitment.columns[1],
    );

    let numerator_01 = &numerator_0 + &numerator_1;
    ldm_per_query.write("numerator_composition_01", &numerator_01)?;
    ldm_per_query.write("composition_2_val", &composition_decommitment.columns[2])?;
    ldm_per_query.write("composition_3_val", &composition_decommitment.columns[3])?;

    ldm.save()?;
    ldm_per_query.save()?;

    Ok(cs)
}
