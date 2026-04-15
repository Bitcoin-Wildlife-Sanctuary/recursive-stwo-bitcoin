//! Line coefficient scripts for PlonkWithPoseidon
//!
//! These scripts compute line coefficients for OODS verification.
//! Due to the large number of columns (130+), we need ~69 scripts.
//!
//! Column organization:
//! - Shifted interaction columns (8): at shifted OODS point
//! - Original columns at log_size 24 (126): at OODS point
//! - Composition columns at log_size 27 (4): at OODS point

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

/// Generate line coefficients for shifted interaction columns
/// These are evaluated at the shifted OODS point (oods_point * g^{-1})
/// Uses the same randomizer family as original columns (log_size 24)
pub fn generate_shifted_cs(
    ldm: &mut LDM,
    counter: usize,
    shifted_labels: &[String],
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

    // Use the same randomizer family as original log_size 24 columns
    // Shifted columns use counters 0..shifted_count
    let mut line_coeff_randomizer = LineCoeffRandomizerBar {
        alpha: ldm.read(format!("line_coeff_randomizer_24_alpha_{}", counter))?,
    };
    let table = TableBar::new_constant(&cs, ())?;

    // Process 2 columns per script
    for i in counter * 2..min(shifted_labels.len(), counter * 2 + 2) {
        let value: QM31Bar = ldm.read(shifted_labels[i].to_string())?;
        let alpha =
            line_coeff_randomizer.get_and_update(&table, &after_sampled_values_random_coeff);
        let coeff = complex_conjugate_line_coeffs_var(&table, &oods_shifted_point, &value, &alpha)?;
        ldm.write(
            format!("column_line_coeff_{}", shifted_labels[i]),
            &coeff,
        )?;
    }

    ldm.write(
        format!("line_coeff_randomizer_24_alpha_{}", counter + 1),
        &line_coeff_randomizer.alpha,
    )?;

    ldm.save()?;
    Ok(cs)
}

/// Generate line coefficients for original columns at log_size 24
/// These are evaluated at the OODS point
pub fn generate_original_24_cs(
    ldm: &mut LDM,
    counter: usize,
    original_labels: &[String],
    randomizer_offset: usize,
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

    let alpha_idx = counter + randomizer_offset;
    let mut line_coeff_randomizer = LineCoeffRandomizerBar {
        alpha: ldm.read(format!("line_coeff_randomizer_24_alpha_{}", alpha_idx))?,
    };
    let table = TableBar::new_constant(&cs, ())?;

    // Process 2 columns per script
    for i in counter * 2..min(original_labels.len(), counter * 2 + 2) {
        let value: QM31Bar = ldm.read(original_labels[i].to_string())?;
        let alpha =
            line_coeff_randomizer.get_and_update(&table, &after_sampled_values_random_coeff);
        let coeff = complex_conjugate_line_coeffs_var(&table, &oods_point, &value, &alpha)?;
        ldm.write(
            format!("column_line_coeff_{}", original_labels[i]),
            &coeff,
        )?;
    }

    ldm.write(
        format!("line_coeff_randomizer_24_alpha_{}", alpha_idx + 1),
        &line_coeff_randomizer.alpha,
    )?;

    ldm.save()?;
    Ok(cs)
}

/// Generate line coefficients for composition columns at log_size 27
pub fn generate_composition_cs(
    ldm: &mut LDM,
    counter: usize,
    composition_labels: &[String],
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
        alpha: ldm.read(format!("line_coeff_randomizer_27_alpha_{}", counter))?,
    };
    let table = TableBar::new_constant(&cs, ())?;

    // Process 2 columns per script
    for i in counter * 2..min(composition_labels.len(), counter * 2 + 2) {
        let value: QM31Bar = ldm.read(composition_labels[i].to_string())?;
        let alpha =
            line_coeff_randomizer.get_and_update(&table, &after_sampled_values_random_coeff);
        let coeff = complex_conjugate_line_coeffs_var(&table, &oods_point, &value, &alpha)?;
        ldm.write(
            format!("column_line_coeff_{}", composition_labels[i]),
            &coeff,
        )?;
    }

    ldm.write(
        format!("line_coeff_randomizer_27_alpha_{}", counter + 1),
        &line_coeff_randomizer.alpha,
    )?;

    ldm.save()?;
    Ok(cs)
}

/// Labels for shifted interaction columns (8 total)
pub fn generate_shifted_interaction_labels() -> Vec<String> {
    vec![
        "plonk_interaction_4_shifted".to_string(),
        "plonk_interaction_5_shifted".to_string(),
        "plonk_interaction_6_shifted".to_string(),
        "plonk_interaction_7_shifted".to_string(),
        "poseidon_interaction_4_shifted".to_string(),
        "poseidon_interaction_5_shifted".to_string(),
        "poseidon_interaction_6_shifted".to_string(),
        "poseidon_interaction_7_shifted".to_string(),
    ]
}

/// Labels for original columns at log_size 24 (126 total)
pub fn generate_original_logsize_24_labels() -> Vec<String> {
    let mut labels = Vec::new();

    // PLONK preprocessed (10)
    labels.extend([
        "plonk_prep_a_wire", "plonk_prep_b_wire", "plonk_prep_c_wire",
        "plonk_prep_op", "plonk_prep_mult_a", "plonk_prep_mult_b",
        "plonk_prep_mult_c", "plonk_prep_poseidon_wire", "plonk_prep_mult_poseidon",
        "plonk_prep_enforce_c_m31",
    ].map(String::from));

    // Poseidon preprocessed (40)
    labels.extend([
        "poseidon_prep_is_first_round", "poseidon_prep_is_last_round",
        "poseidon_prep_is_full_round", "poseidon_prep_round_id",
    ].map(String::from));
    for i in 0..16 {
        labels.push(format!("poseidon_prep_rc0_{}", i));
    }
    for i in 0..16 {
        labels.push(format!("poseidon_prep_rc1_{}", i));
    }
    labels.extend([
        "poseidon_prep_external_idx_1", "poseidon_prep_external_idx_2",
        "poseidon_prep_is_external_idx_1_nonzero", "poseidon_prep_is_external_idx_2_nonzero",
    ].map(String::from));

    // PLONK trace (12)
    for i in 0..4 {
        labels.push(format!("trace_a_val_{}", i));
    }
    for i in 0..4 {
        labels.push(format!("trace_b_val_{}", i));
    }
    for i in 0..4 {
        labels.push(format!("trace_c_val_{}", i));
    }

    // Poseidon trace (48)
    for i in 0..16 {
        labels.push(format!("poseidon_trace_in_state_{}", i));
    }
    for i in 0..16 {
        labels.push(format!("poseidon_trace_intermediate_{}", i));
    }
    for i in 0..16 {
        labels.push(format!("poseidon_trace_out_state_{}", i));
    }

    // PLONK interaction (8)
    for i in 0..8 {
        labels.push(format!("plonk_interaction_{}", i));
    }

    // Poseidon interaction (8)
    for i in 0..8 {
        labels.push(format!("poseidon_interaction_{}", i));
    }

    assert_eq!(labels.len(), 126, "Expected 126 original columns");
    labels
}

/// Labels for composition columns at log_size 27 (4 total)
pub fn generate_composition_labels() -> Vec<String> {
    vec![
        "composition_0".to_string(),
        "composition_1".to_string(),
        "composition_2".to_string(),
        "composition_3".to_string(),
    ]
}

/// Calculate total number of line coefficient scripts needed
pub fn count_line_coeff_scripts() -> (usize, usize, usize, usize) {
    let shifted = generate_shifted_interaction_labels().len();
    let original = generate_original_logsize_24_labels().len();
    let composition = generate_composition_labels().len();

    let shifted_scripts = (shifted + 1) / 2;
    let original_scripts = (original + 1) / 2;
    let composition_scripts = (composition + 1) / 2;
    let total = shifted_scripts + original_scripts + composition_scripts;

    (shifted_scripts, original_scripts, composition_scripts, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_counts() {
        let shifted = generate_shifted_interaction_labels();
        let original = generate_original_logsize_24_labels();
        let composition = generate_composition_labels();

        println!("Shifted interaction labels: {}", shifted.len());
        println!("Original log_size 24 labels: {}", original.len());
        println!("Composition labels: {}", composition.len());
        println!("Total columns: {}", shifted.len() + original.len() + composition.len());

        assert_eq!(shifted.len(), 8);
        assert_eq!(original.len(), 126);
        assert_eq!(composition.len(), 4);
    }

    #[test]
    fn test_script_count() {
        let (shifted, original, composition, total) = count_line_coeff_scripts();
        println!("\nLine coefficient scripts needed:");
        println!("  Shifted: {}", shifted);
        println!("  Original (log_size 24): {}", original);
        println!("  Composition (log_size 27): {}", composition);
        println!("  Total: {}", total);

        assert_eq!(shifted, 4);
        assert_eq!(original, 63);
        assert_eq!(composition, 2);
        assert_eq!(total, 69);
    }
}
