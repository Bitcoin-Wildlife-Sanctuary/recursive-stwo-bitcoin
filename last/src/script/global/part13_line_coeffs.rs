use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::circle::CirclePointQM31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::{
    complex_conjugate_line_coeffs_var, LineCoeffRandomizerBar,
};
use std::cmp::min;

pub fn generate_cs(
    ldm: &mut LDM,
    counter: usize,
    oods_original_logsize_26_labels: &[String],
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let after_sampled_values_random_coeff: QM31Bar =
        ldm.read("after_sampled_values_random_coeff")?;
    let oods_x: QM31Bar = ldm.read("oods_x")?;
    let oods_y: QM31Bar = ldm.read("oods_y")?;
    let oods_point = CirclePointQM31Bar {
        x: oods_x,
        y: oods_y,
    };
    let mut line_coeff_randomizer = LineCoeffRandomizerBar {
        alpha: ldm.read(format!("line_coeff_randomizer_26_alpha_{}", counter + 2))?,
    };
    let table = TableBar::new_constant(&cs, ())?;

    for i in counter * 2..min(oods_original_logsize_26_labels.len(), counter * 2 + 2) {
        let value: QM31Bar = ldm.read(oods_original_logsize_26_labels[i].to_string())?;
        let alpha =
            line_coeff_randomizer.get_and_update(&table, &after_sampled_values_random_coeff);
        let coeff = complex_conjugate_line_coeffs_var(&table, &oods_point, &value, &alpha)?;
        ldm.write(
            format!("column_line_coeff_{}", oods_original_logsize_26_labels[i]),
            &coeff,
        )?;
    }

    ldm.write(
        format!("line_coeff_randomizer_26_alpha_{}", counter + 2 + 1),
        &line_coeff_randomizer.alpha,
    )?;

    ldm.save()?;
    Ok(cs)
}

pub fn generate_oods_original_logsize_26_labels() -> Vec<String> {
    vec![
        "preprocessed_a_wire".to_string(),
        "preprocessed_b_wire".to_string(),
        "preprocessed_c_wire".to_string(),
        "preprocessed_op1".to_string(),
        "preprocessed_op2".to_string(),
        "preprocessed_op3".to_string(),
        "preprocessed_op4".to_string(),
        "preprocessed_mult_c".to_string(),
        "trace_a_val_0".to_string(),
        "trace_a_val_1".to_string(),
        "trace_a_val_2".to_string(),
        "trace_a_val_3".to_string(),
        "trace_b_val_0".to_string(),
        "trace_b_val_1".to_string(),
        "trace_b_val_2".to_string(),
        "trace_b_val_3".to_string(),
        "trace_c_val_0".to_string(),
        "trace_c_val_1".to_string(),
        "trace_c_val_2".to_string(),
        "trace_c_val_3".to_string(),
        "interaction_0".to_string(),
        "interaction_1".to_string(),
        "interaction_2".to_string(),
        "interaction_3".to_string(),
    ]
}

pub fn generate_oods_original_logsize_28_labels() -> Vec<String> {
    vec![
        "composition_0".to_string(),
        "composition_1".to_string(),
        "composition_2".to_string(),
        "composition_3".to_string(),
    ]
}
