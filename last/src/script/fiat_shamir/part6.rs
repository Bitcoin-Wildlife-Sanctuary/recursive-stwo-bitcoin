use anyhow::Result;
use num_traits::One;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use stwo_prover::core::fields::qm31::QM31;

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

    let a_val = &(&(&trace_a_val_0 + &trace_a_val_1.shift_by_i()) + &trace_a_val_2.shift_by_j())
        + &trace_a_val_3;
    let b_val = &(&(&trace_b_val_0 + &trace_b_val_1.shift_by_i()) + &trace_b_val_2.shift_by_j())
        + &trace_b_val_3;

    let preprocessed_op1: QM31Bar = ldm.read("preprocessed_op1")?;
    let preprocessed_op3: QM31Bar = ldm.read("preprocessed_op3")?;
    let preprocessed_op4: QM31Bar = ldm.read("preprocessed_op4")?;
    let one = QM31Bar::new_constant(&cs, QM31::one())?;
    let one_minus_op1 = &one - &preprocessed_op1;
    let one_minus_op3 = &one - &preprocessed_op3;
    let one_minus_op4 = &one - &preprocessed_op4;

    let table = TableBar::new_constant(&cs, ())?;

    let is_arith = &one_minus_op3 * (&table, &one_minus_op4);

    let trace_c_val_0: QM31Bar = ldm.read("trace_c_val_0")?;
    let trace_c_val_1: QM31Bar = ldm.read("trace_c_val_1")?;
    let trace_c_val_2: QM31Bar = ldm.read("trace_c_val_2")?;
    let trace_c_val_3: QM31Bar = ldm.read("trace_c_val_3")?;
    let c_val = &(&(&trace_c_val_0 + &trace_c_val_1.shift_by_i()) + &trace_c_val_2.shift_by_j())
        + &trace_c_val_3;

    let mut sum: QM31Bar = ldm.read("arith_sum_part_5")?;
    sum = &sum + &c_val;
    sum = &sum - &(&(&is_arith * (&table, &preprocessed_op1)) * (&table, &(&a_val + &b_val)));
    sum = &sum - &(&(&one_minus_op1 * (&table, &a_val)) * (&table, &b_val));

    ldm.write("arith_sum_part_6", &sum)?;

    ldm.save()?;
    Ok(cs)
}
