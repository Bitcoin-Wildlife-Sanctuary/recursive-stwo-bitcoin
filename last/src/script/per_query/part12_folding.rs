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

    let mut query: M31Bar = ldm_per_query.read("query_13")?;
    let layer_14: QM31Bar = ldm_per_query.read("layer_14")?;
    let table = TableBar::new_constant(&cs, ())?;

    let layer_13 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_14")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_14")?;
        layer_14.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_13")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_14")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_12 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_15")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_15")?;
        layer_13.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_12")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_15")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_11 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_16")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_16")?;
        layer_12.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_11")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_16")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_10 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_17")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_17")?;
        layer_11.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        hi.drop();

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_10")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_17")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let last_layer: QM31Bar = ldm.read("last_layer_poly")?;
    layer_10.equalverify(&last_layer)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
