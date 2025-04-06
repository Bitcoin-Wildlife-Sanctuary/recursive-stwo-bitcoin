use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::input_sum::InputSumBar;
use std::cmp::min;

pub fn generate_cs(
    ldm: &mut LDM,
    counter: usize,
    input_labels: &[String],
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let alpha: QM31Bar = ldm.read(format!("input_acc_alpha_{}", counter))?;
    let cur: QM31Bar = ldm.read(format!("input_acc_cur_{}", counter))?;
    let sum: QM31Bar = ldm.read(format!("input_acc_sum_{}", counter))?;

    let mut input_acc = InputSumBar { alpha, cur, sum };

    let table = TableBar::new_constant(&cs, ())?;

    for i in (counter * 7)..min(input_labels.len(), counter * 7 + 7) {
        input_acc.accumulate_from_ldm(&table, ldm, &input_labels[i])?;
    }

    ldm.write(format!("input_acc_alpha_{}", counter + 1), &input_acc.alpha)?;
    ldm.write(format!("input_acc_cur_{}", counter + 1), &input_acc.cur)?;
    ldm.write(format!("input_acc_sum_{}", counter + 1), &input_acc.sum)?;

    ldm.save()?;
    Ok(cs)
}
