use crate::script::hints::folding::{
    LastFirstLayerHints, LastInnerLayersHints, LastSinglePairMerkleProofBar,
};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use std::collections::BTreeMap;

pub fn generate_cs(
    query_idx: usize,
    last_first_layer_hints: &LastFirstLayerHints,
    last_inner_layers_hints: &LastInnerLayersHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let query_28: M31Bar = ldm.read(format!("query_{}", query_idx))?;
    let first_layer_decommitment = LastSinglePairMerkleProofBar::new_hint(
        &cs,
        last_first_layer_hints.merkle_proofs[query_idx].clone(),
    )?;
    let first_layer_commitment: Sha256HashBar = ldm.read("first_layer_commitment")?;
    first_layer_decommitment.verify(&query_28, 28, &first_layer_commitment)?;

    ldm_per_query.write(
        "first_layer_self_26",
        &first_layer_decommitment.self_columns[&26],
    )?;
    ldm_per_query.write(
        "first_layer_sibling_26",
        &first_layer_decommitment.siblings_columns[&26],
    )?;

    let mut inner_layer_self_columns = BTreeMap::new();
    let mut inner_layer_sibling_columns = BTreeMap::new();

    for i in 0..18 {
        let inner_layer_decommitment = LastSinglePairMerkleProofBar::new_hint(
            &cs,
            last_inner_layers_hints.merkle_proofs[&(27 - i)][query_idx].clone(),
        )?;
        let inner_layer_commitment: Sha256HashBar =
            ldm.read(format!("inner_layer_commitment_{}", i))?;
        inner_layer_decommitment.verify(&query_28, 28, &inner_layer_commitment)?;
        inner_layer_self_columns.insert(
            i,
            inner_layer_decommitment.self_columns[&((27 - i) as usize)].clone(),
        );
        inner_layer_sibling_columns.insert(
            i,
            inner_layer_decommitment.siblings_columns[&((27 - i) as usize)].clone(),
        );
    }

    for i in 2..18 {
        ldm_per_query.write(
            format!("inner_layer_self_{}", i),
            &inner_layer_self_columns[&i],
        )?;
        ldm_per_query.write(
            format!("inner_layer_sibling_{}", i),
            &inner_layer_sibling_columns[&i],
        )?;
    }

    let table = TableBar::new_constant(&cs, ())?;
    let first_layer_alpha: QM31Bar = ldm.read("first_layer_alpha")?;

    let mut query = query_28.clone();
    let folded_into_28 = {
        let left = &first_layer_decommitment.self_columns[&28];
        let right = &first_layer_decommitment.siblings_columns[&28];

        let row_28: QM31Bar = ldm_per_query.read("row_28")?;
        row_28.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);

        let point_28_y_inv: M31Bar = ldm_per_query.read("point_28_y_inv")?;
        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_28_y_inv);
        &(&t1 * (&table, &first_layer_alpha)) + &t0
    };

    let layer_27 = {
        let left = &inner_layer_self_columns[&0];
        let right = &inner_layer_sibling_columns[&0];

        folded_into_28.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_27")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_0")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };

    let layer_26 = {
        let left = &first_layer_decommitment.self_columns[&26];
        let right = &first_layer_decommitment.siblings_columns[&26];

        let row_26: QM31Bar = ldm_per_query.read("row_26")?;
        row_26.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);

        let point_26_y_inv: M31Bar = ldm_per_query.read("point_26_y_inv")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_1")?;
        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_26_y_inv);
        let folded_into = &(&t1 * (&table, &inner_layer_alpha)) + &t0;

        let inner_layer_alpha_squared: QM31Bar = ldm.read("inner_layer_alpha_1_squared")?;

        let left = &inner_layer_self_columns[&1];
        let right = &inner_layer_sibling_columns[&1];
        layer_27.equalverify(&left)?;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_26")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        let res = &(&t1 * (&table, &inner_layer_alpha)) + &t0;

        let folded = &inner_layer_alpha_squared * (&table, &res);
        &folded + &folded_into
    };
    ldm_per_query.write("layer_26", &layer_26)?;
    ldm_per_query.write("query_25", &query)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
