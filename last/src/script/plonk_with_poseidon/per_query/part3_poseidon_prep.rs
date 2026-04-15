//! PlonkWithPoseidon Per-Query Part 3: Poseidon Preprocessed Numerators
//!
//! This script computes numerators for Poseidon preprocessed columns (40 columns).
//! The column values were stored by part2.

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use num_traits::Zero;
use stwo_prover::core::fields::qm31::QM31;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

/// Generate Poseidon preprocessed column labels (40 columns)
fn poseidon_prep_labels() -> Vec<String> {
    let mut labels = vec![
        "poseidon_prep_is_first_round".to_string(),
        "poseidon_prep_is_last_round".to_string(),
        "poseidon_prep_is_full_round".to_string(),
        "poseidon_prep_round_id".to_string(),
    ];
    for i in 0..16 {
        labels.push(format!("poseidon_prep_rc0_{}", i));
    }
    for i in 0..16 {
        labels.push(format!("poseidon_prep_rc1_{}", i));
    }
    labels.extend([
        "poseidon_prep_external_idx_1".to_string(),
        "poseidon_prep_external_idx_2".to_string(),
        "poseidon_prep_is_external_idx_1_nonzero".to_string(),
        "poseidon_prep_is_external_idx_2_nonzero".to_string(),
    ]);
    assert_eq!(labels.len(), 40);
    labels
}

pub fn generate_cs(
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_24_y: M31Bar = ldm_per_query.read("point_24_y")?;

    let labels = poseidon_prep_labels();
    let mut numerator_poseidon_prep = QM31Bar::new_constant(&cs, QM31::zero())?;

    for (i, label) in labels.iter().enumerate() {
        let val: M31Bar = ldm_per_query.read(format!("poseidon_prep_val_{}", i))?;
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &val);
        numerator_poseidon_prep = &numerator_poseidon_prep + &numerator;
    }

    // Combine with PLONK preprocessed numerator
    let numerator_plonk_prep: QM31Bar = ldm_per_query.read("numerator_plonk_prep")?;
    let numerator_preprocessed = &numerator_plonk_prep + &numerator_poseidon_prep;

    ldm_per_query.write("numerator_preprocessed", &numerator_preprocessed)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
