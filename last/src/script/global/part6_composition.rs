use anyhow::Result;
use num_traits::One;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::composition::PointEvaluationAccumulatorBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use stwo_prover::core::fields::qm31::QM31;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let trace_a_val: QM31Bar = ldm.read("trace_a_val")?;
    let trace_b_val: QM31Bar = ldm.read("trace_b_val")?;

    let preprocessed_op1: QM31Bar = ldm.read("preprocessed_op1")?;
    let preprocessed_op3: QM31Bar = ldm.read("preprocessed_op3")?;
    let preprocessed_op4: QM31Bar = ldm.read("preprocessed_op4")?;
    let one = QM31Bar::new_constant(&cs, QM31::one())?;
    let one_minus_op1 = &one - &preprocessed_op1;
    let one_minus_op3 = &one - &preprocessed_op3;
    let one_minus_op4 = &one - &preprocessed_op4;

    let table = TableBar::new_constant(&cs, ())?;

    let is_arith = &one_minus_op3 * (&table, &one_minus_op4);

    let trace_c_val: QM31Bar = ldm.read("trace_c_val")?;

    let mut sum: QM31Bar = ldm.read("arith_sum_part_5")?;
    sum = &sum + &trace_c_val;
    sum = &sum
        - &(&(&is_arith * (&table, &preprocessed_op1)) * (&table, &(&trace_a_val + &trace_b_val)));
    sum = &sum - &(&(&one_minus_op1 * (&table, &trace_a_val)) * (&table, &trace_b_val));

    let random_coeff: QM31Bar = ldm.read("random_coeff")?;
    let accumulation: QM31Bar = ldm.read("eval_acc_accumulation_part4")?;

    let mut eval_acc = PointEvaluationAccumulatorBar {
        random_coeff,
        accumulation,
    };

    eval_acc.accumulate(&table, &sum);
    ldm.write("eval_acc_accumulation_part6", &eval_acc.accumulation)?;

    let first_layer_alpha: QM31Bar = ldm.read("first_layer_alpha")?;
    ldm.write(
        "first_layer_alpha_squared",
        &(&first_layer_alpha * (&table, &first_layer_alpha)),
    )?;

    let inner_layer_alpha_1: QM31Bar = ldm.read("inner_layer_alpha_1")?;
    ldm.write(
        "inner_layer_alpha_1_squared",
        &(&inner_layer_alpha_1 * (&table, &inner_layer_alpha_1)),
    )?;

    ldm.save()?;
    Ok(cs)
}
