use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::composition::PointEvaluationAccumulatorBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let random_coeff: QM31Bar = ldm.read("random_coeff")?;
    let accumulation: QM31Bar = ldm.read("eval_acc_accumulation_part3")?;

    let preprocessed_op2: QM31Bar = ldm.read("preprocessed_op2")?;
    let is_pow5 = preprocessed_op2.clone();

    let trace_a_val_2: QM31Bar = ldm.read("trace_a_val_2")?;
    let trace_a_val_3: QM31Bar = ldm.read("trace_a_val_3")?;
    let trace_b_val_2: QM31Bar = ldm.read("trace_b_val_2")?;
    let trace_b_val_3: QM31Bar = ldm.read("trace_b_val_3")?;

    let table = TableBar::new_constant(&cs, ())?;

    let mut a_val_2_pow4 = &trace_a_val_2 * (&table, &trace_a_val_2);
    a_val_2_pow4 = &a_val_2_pow4 * (&table, &a_val_2_pow4);

    let mut a_val_3_pow4 = &trace_a_val_3 * (&table, &trace_a_val_3);
    a_val_3_pow4 = &a_val_3_pow4 * (&table, &a_val_3_pow4);

    let mut eval_acc = PointEvaluationAccumulatorBar {
        random_coeff,
        accumulation,
    };

    eval_acc.accumulate(
        &table,
        &(&(&a_val_2_pow4 - &trace_b_val_2) * (&table, &is_pow5)),
    );
    eval_acc.accumulate(
        &table,
        &(&(&a_val_3_pow4 - &trace_b_val_3) * (&table, &is_pow5)),
    );

    ldm.write("eval_acc_accumulation_part4", &eval_acc.accumulation)?;

    ldm.save()?;
    Ok(cs)
}
