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
    oods_shifted_logsize_26_labels: &[String],
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let after_sampled_values_random_coeff: QM31Bar =
        ldm.read("after_sampled_values_random_coeff")?;
    let oods_shifted_x: QM31Bar = ldm.read("oods_shifted_x")?;
    let oods_shifted_y: QM31Bar = ldm.read("oods_shifted_y")?;
    let oods_shifted_point = CirclePointQM31Bar {
        x: oods_shifted_x,
        y: oods_shifted_y,
    };
    let mut line_coeff_randomizer = LineCoeffRandomizerBar {
        alpha: ldm.read(format!("line_coeff_randomizer_26_alpha_{}", counter))?,
    };
    let table = TableBar::new_constant(&cs, ())?;

    for i in counter * 2..min(oods_shifted_logsize_26_labels.len(), counter * 2 + 2) {
        let value: QM31Bar = ldm.read(oods_shifted_logsize_26_labels[i].to_string())?;
        let alpha =
            line_coeff_randomizer.get_and_update(&table, &after_sampled_values_random_coeff);
        let coeff = complex_conjugate_line_coeffs_var(&table, &oods_shifted_point, &value, &alpha)?;
        ldm.write(
            format!("column_line_coeff_{}", oods_shifted_logsize_26_labels[i]),
            &coeff,
        )?;
    }

    ldm.write(
        format!("line_coeff_randomizer_26_alpha_{}", counter + 1),
        &line_coeff_randomizer.alpha,
    )?;

    ldm.save()?;
    Ok(cs)
}

pub fn generate_oods_shifted_logsize_26_labels() -> Vec<String> {
    vec![
        "interaction_prev_0".to_string(),
        "interaction_prev_1".to_string(),
        "interaction_prev_2".to_string(),
        "interaction_prev_3".to_string(),
    ]
}
