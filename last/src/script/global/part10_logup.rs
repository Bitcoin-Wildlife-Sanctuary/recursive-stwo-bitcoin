use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let trace_a_val: QM31Bar = ldm.read("trace_a_val")?;
    let trace_b_val: QM31Bar = ldm.read("trace_b_val")?;
    let trace_c_val: QM31Bar = ldm.read("trace_c_val")?;

    let preprocessed_a_wire: QM31Bar = ldm.read("preprocessed_a_wire")?;
    let preprocessed_b_wire: QM31Bar = ldm.read("preprocessed_b_wire")?;
    let preprocessed_c_wire: QM31Bar = ldm.read("preprocessed_c_wire")?;
    let preprocessed_mult_c: QM31Bar = ldm.read("preprocessed_mult_c")?;

    let z: QM31Bar = ldm.read("z")?;
    let alpha: QM31Bar = ldm.read("alpha")?;

    let table = TableBar::new_constant(&cs, ())?;

    let a_denom = &(&trace_a_val + &(&preprocessed_a_wire * (&table, &alpha))) - &z;
    let b_denom = &(&trace_b_val + &(&preprocessed_b_wire * (&table, &alpha))) - &z;

    // 1/a + 1/b = (a+b)/ab
    let ab_num = &a_denom + &b_denom;
    let ab_denom = &a_denom * (&table, &b_denom);

    let c_num = preprocessed_mult_c.clone();
    let c_denom = &(&trace_c_val + &(&preprocessed_c_wire * (&table, &alpha))) - &z;

    // a/b + c/d = (ad+bc)/bd
    let abc_num = &(&ab_num * (&table, &c_denom)) + &(&c_num * (&table, &ab_denom));
    let abc_denom = &ab_denom * (&table, &c_denom);

    ldm.write("relation_num", &abc_num)?;
    ldm.write("relation_denom", &abc_denom)?;

    ldm.save()?;
    Ok(cs)
}
