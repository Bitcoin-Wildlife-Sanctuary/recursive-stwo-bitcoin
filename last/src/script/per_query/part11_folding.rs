use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM, ldm_per_query: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let mut query: M31Bar = ldm_per_query.read("query_17")?;
    let layer_18: QM31Bar = ldm_per_query.read("layer_18")?;
    let table = TableBar::new_constant(&cs, ())?;

    let layer_17 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_10")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_10")?;
        layer_18.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_17")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_10")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_16 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_11")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_11")?;
        layer_17.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_16")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_11")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_15 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_12")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_12")?;
        layer_16.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_15")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_12")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_14 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_13")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_13")?;
        layer_15.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_14")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_13")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    ldm_per_query.write("query_13", &query)?;
    ldm_per_query.write("layer_14", &layer_14)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
