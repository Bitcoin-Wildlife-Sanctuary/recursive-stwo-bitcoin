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

    let mut query: M31Bar = ldm_per_query.read("query_21")?;
    let layer_22: QM31Bar = ldm_per_query.read("layer_22")?;
    let table = TableBar::new_constant(&cs, ())?;

    let layer_21 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_6")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_6")?;
        layer_22.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_21")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_6")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_20 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_7")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_7")?;
        layer_21.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_20")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_7")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_19 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_8")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_8")?;
        layer_20.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_19")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_8")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    let layer_18 = {
        let left: QM31Bar = ldm_per_query.read("inner_layer_self_9")?;
        let right: QM31Bar = ldm_per_query.read("inner_layer_sibling_9")?;
        layer_19.equalverify(&left)?;

        let (hi, lo) = split_hi_lo(&query, 1)?;
        query = hi;

        let (left, right) = left.conditional_swap(&right, &lo);
        let point_x_inv: M31Bar = ldm_per_query.read("twiddle_18")?;
        let inner_layer_alpha: QM31Bar = ldm.read("inner_layer_alpha_9")?;

        let t0 = &left + &right;
        let t1 = &(&left - &right) * (&table, &point_x_inv);
        &(&t1 * (&table, &inner_layer_alpha)) + &t0
    };
    ldm_per_query.write("query_17", &query)?;
    ldm_per_query.write("layer_18", &layer_18)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
