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

    let mut query: M31Bar = ldm_per_query.read("query_25")?;
    let layer_26: QM31Bar = ldm_per_query.read("layer_26")?;
    let table = TableBar::new_constant(&cs, ())?;

    let layer_25 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_2")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_2")?;
        layer_26.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_25")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_2")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_24 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_3")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_3")?;
        layer_25.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_24")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_3")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_23 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_4")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_4")?;
        layer_24.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_23")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_4")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_22 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_5")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_5")?;
        layer_23.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_22")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_5")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    ldm_per_query.write("query_21", &query)?;
    ldm_per_query.write("layer_22", &layer_22)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
