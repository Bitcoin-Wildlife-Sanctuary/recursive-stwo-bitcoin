use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let trace_a_val_0: QM31Bar = ldm.read("trace_a_val_0")?;
    let trace_a_val_1: QM31Bar = ldm.read("trace_a_val_1")?;
    let trace_a_val_2: QM31Bar = ldm.read("trace_a_val_2")?;
    let trace_a_val_3: QM31Bar = ldm.read("trace_a_val_3")?;

    let trace_b_val_0: QM31Bar = ldm.read("trace_b_val_0")?;
    let trace_b_val_1: QM31Bar = ldm.read("trace_b_val_1")?;
    let trace_b_val_2: QM31Bar = ldm.read("trace_b_val_2")?;
    let trace_b_val_3: QM31Bar = ldm.read("trace_b_val_3")?;

    let trace_c_val_0: QM31Bar = ldm.read("trace_c_val_0")?;
    let trace_c_val_1: QM31Bar = ldm.read("trace_c_val_1")?;
    let trace_c_val_2: QM31Bar = ldm.read("trace_c_val_2")?;
    let trace_c_val_3: QM31Bar = ldm.read("trace_c_val_3")?;

    let preprocessed_a_wire: QM31Bar = ldm.read("preprocessed_a_wire")?;
    let preprocessed_b_wire: QM31Bar = ldm.read("preprocessed_b_wire")?;
    let preprocessed_c_wire: QM31Bar = ldm.read("preprocessed_c_wire")?;
    let preprocessed_mult_c: QM31Bar = ldm.read("preprocessed_mult_c")?;

    let a_val = &(&(&trace_a_val_0 + &trace_a_val_1.shift_by_i()) + &trace_a_val_2.shift_by_j())
        + &trace_a_val_3.shift_by_ij();
    let b_val = &(&(&trace_b_val_0 + &trace_b_val_1.shift_by_i()) + &trace_b_val_2.shift_by_j())
        + &trace_b_val_3.shift_by_ij();
    let c_val = &(&(&trace_c_val_0 + &trace_c_val_1.shift_by_i()) + &trace_c_val_2.shift_by_j())
        + &trace_c_val_3.shift_by_ij();

    let z: QM31Bar = ldm.read("z")?;
    let alpha: QM31Bar = ldm.read("alpha")?;

    let table = TableBar::new_constant(&cs, ())?;

    let a_denom = &(&a_val + &(&preprocessed_a_wire * (&table, &alpha))) - &z;
    let b_denom = &(&b_val + &(&preprocessed_b_wire * (&table, &alpha))) - &z;

    // 1/a + 1/b = (a+b)/ab
    let ab_num = &a_denom + &b_denom;
    let ab_denom = &a_denom * (&table, &b_denom);

    let c_num = preprocessed_mult_c.clone();
    let c_denom = &(&c_val + &(&preprocessed_c_wire * (&table, &alpha))) - &z;

    // a/b + c/d = (ad+bc)/bd
    let abc_num = &(&ab_num * (&table, &c_denom)) + &(&c_num * (&table, &ab_denom));
    let abc_denom = &ab_denom * (&table, &c_denom);

    ldm.write("relation_num", &abc_num)?;
    ldm.write("relation_denom", &abc_denom)?;

    ldm.save()?;
    Ok(cs)
}
