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

    let mut grand_sum = &trace_a_val_0 + &trace_a_val_1;
    grand_sum = &grand_sum + &trace_a_val_2;
    grand_sum = &grand_sum + &trace_a_val_3;
    grand_sum = &grand_sum + &trace_b_val_0;
    grand_sum = &grand_sum + &trace_b_val_1;
    grand_sum = &grand_sum + &trace_b_val_2;
    grand_sum = &grand_sum + &trace_b_val_3;

    grand_sum = &(&(&grand_sum + &grand_sum.shift_by_i()) + &grand_sum.shift_by_j())
        + &grand_sum.shift_by_ij();

    let table = TableBar::new_constant(&cs, ())?;

    let x0 = &trace_a_val_0 * (&table, &trace_b_val_0);
    let x1 = &trace_a_val_1 * (&table, &trace_b_val_1);
    let x2 = &trace_a_val_2 * (&table, &trace_b_val_2);
    let x3 = &trace_a_val_3 * (&table, &trace_b_val_3);

    let t0 = &x0 + &x1;
    let t02 = &t0 + &t0;
    let t1 = &x2 + &x3;
    let t12 = &t1 + &t1;
    let t2 = &(&x1 + &x1) + &t1;
    let t3 = &(&x3 + &x3) + &t0;
    let t4 = &(&t12 + &t12) + &t3;
    let t5 = &(&t02 + &t02) + &t2;
    let t6 = &t3 + &t5;
    let t7 = &t2 + &t4;

    let m4_result_0 = t6;
    let m4_result_1 = t5;
    let m4_result_2 = t7;
    let m4_result_3 = t4;

    let preprocessed_op3: QM31Bar = ldm.read("preprocessed_op3")?;
    let preprocessed_op4: QM31Bar = ldm.read("preprocessed_op4")?;

    let is_grand_sum = &preprocessed_op3 * (&table, &preprocessed_op4);
    let is_m4 = &preprocessed_op3 - &is_grand_sum;
    let is_hadamard_product = &preprocessed_op4 - &is_grand_sum;

    let m4_result = &(&(&(&m4_result_0 + &m4_result_1.shift_by_i()) + &m4_result_2.shift_by_j())
        + &m4_result_3.shift_by_ij())
        * (&table, &is_m4);
    let hadamard_product_result = &(&(&(&x0 + &x1.shift_by_i()) + &x2.shift_by_j())
        + &x3.shift_by_ij())
        * (&table, &is_hadamard_product);

    let mut sum = -&m4_result;
    sum = &sum - &hadamard_product_result;

    let grand_sum_result = &grand_sum * (&table, &is_grand_sum);
    sum = &sum - &grand_sum_result;

    ldm.write("arith_sum_part_5", &sum)?;

    ldm.save()?;
    Ok(cs)
}
