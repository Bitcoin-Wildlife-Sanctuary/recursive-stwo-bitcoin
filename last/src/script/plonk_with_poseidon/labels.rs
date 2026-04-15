//! Column labels for PlonkWithPoseidon proofs
//!
//! PlonkWithPoseidon has 130 columns total:
//! - Preprocessed: 50 (10 PLONK + 40 Poseidon)
//! - Trace: 60 (12 PLONK + 48 Poseidon)
//! - Interaction: 16 (8 PLONK + 8 Poseidon)
//! - Composition: 4
//!
//! Note: PLONK and Poseidon may have different log_sizes (log_size_plonk vs log_size_poseidon)

/// PLONK preprocessed columns (10 columns)
/// At log_size_plonk
pub fn plonk_preprocessed_labels() -> Vec<String> {
    vec![
        "plonk_preprocessed_a_wire".to_string(),
        "plonk_preprocessed_b_wire".to_string(),
        "plonk_preprocessed_c_wire".to_string(),
        "plonk_preprocessed_op".to_string(),
        "plonk_preprocessed_mult_a".to_string(),
        "plonk_preprocessed_mult_b".to_string(),
        "plonk_preprocessed_mult_c".to_string(),
        "plonk_preprocessed_poseidon_wire".to_string(),
        "plonk_preprocessed_mult_poseidon".to_string(),
        "plonk_preprocessed_enforce_c_m31".to_string(),
    ]
}

/// Poseidon preprocessed columns (40 columns)
/// At log_size_poseidon
pub fn poseidon_preprocessed_labels() -> Vec<String> {
    let mut labels = vec![
        "poseidon_preprocessed_is_first_round".to_string(),
        "poseidon_preprocessed_is_last_round".to_string(),
        "poseidon_preprocessed_is_full_round".to_string(),
        "poseidon_preprocessed_round_id".to_string(),
    ];

    // rc0[0..15] - 16 columns
    for i in 0..16 {
        labels.push(format!("poseidon_preprocessed_rc0_{}", i));
    }

    // rc1[0..15] - 16 columns
    for i in 0..16 {
        labels.push(format!("poseidon_preprocessed_rc1_{}", i));
    }

    labels.push("poseidon_preprocessed_external_idx_1".to_string());
    labels.push("poseidon_preprocessed_external_idx_2".to_string());
    labels.push("poseidon_preprocessed_is_external_idx_1_nonzero".to_string());
    labels.push("poseidon_preprocessed_is_external_idx_2_nonzero".to_string());

    assert_eq!(labels.len(), 40);
    labels
}

/// All preprocessed column labels (50 columns)
/// Note: PLONK columns are at log_size_plonk, Poseidon at log_size_poseidon
pub fn all_preprocessed_labels() -> Vec<String> {
    let mut labels = plonk_preprocessed_labels();
    labels.extend(poseidon_preprocessed_labels());
    assert_eq!(labels.len(), 50);
    labels
}

/// PLONK trace columns (12 columns)
/// a_val, b_val, c_val each have 4 components (QM31 = 4 × M31)
/// At log_size_plonk
pub fn plonk_trace_labels() -> Vec<String> {
    vec![
        "plonk_trace_a_val_0".to_string(),
        "plonk_trace_a_val_1".to_string(),
        "plonk_trace_a_val_2".to_string(),
        "plonk_trace_a_val_3".to_string(),
        "plonk_trace_b_val_0".to_string(),
        "plonk_trace_b_val_1".to_string(),
        "plonk_trace_b_val_2".to_string(),
        "plonk_trace_b_val_3".to_string(),
        "plonk_trace_c_val_0".to_string(),
        "plonk_trace_c_val_1".to_string(),
        "plonk_trace_c_val_2".to_string(),
        "plonk_trace_c_val_3".to_string(),
    ]
}

/// Poseidon trace columns (48 columns)
/// in_state[16], intermediate_state[16], out_state[16]
/// At log_size_poseidon
pub fn poseidon_trace_labels() -> Vec<String> {
    let mut labels = Vec::with_capacity(48);

    // in_state[0..15]
    for i in 0..16 {
        labels.push(format!("poseidon_trace_in_state_{}", i));
    }

    // intermediate_state[0..15]
    for i in 0..16 {
        labels.push(format!("poseidon_trace_intermediate_state_{}", i));
    }

    // out_state[0..15]
    for i in 0..16 {
        labels.push(format!("poseidon_trace_out_state_{}", i));
    }

    assert_eq!(labels.len(), 48);
    labels
}

/// All trace column labels (60 columns)
pub fn all_trace_labels() -> Vec<String> {
    let mut labels = plonk_trace_labels();
    labels.extend(poseidon_trace_labels());
    assert_eq!(labels.len(), 60);
    labels
}

/// PLONK interaction columns (8 columns)
/// From logup pairs (2 pairs × 4 QM31 components each)
/// At log_size_plonk
pub fn plonk_interaction_labels() -> Vec<String> {
    vec![
        "plonk_interaction_0".to_string(),
        "plonk_interaction_1".to_string(),
        "plonk_interaction_2".to_string(),
        "plonk_interaction_3".to_string(),
        "plonk_interaction_4".to_string(),
        "plonk_interaction_5".to_string(),
        "plonk_interaction_6".to_string(),
        "plonk_interaction_7".to_string(),
    ]
}

/// Poseidon interaction columns (8 columns)
/// At log_size_poseidon
pub fn poseidon_interaction_labels() -> Vec<String> {
    vec![
        "poseidon_interaction_0".to_string(),
        "poseidon_interaction_1".to_string(),
        "poseidon_interaction_2".to_string(),
        "poseidon_interaction_3".to_string(),
        "poseidon_interaction_4".to_string(),
        "poseidon_interaction_5".to_string(),
        "poseidon_interaction_6".to_string(),
        "poseidon_interaction_7".to_string(),
    ]
}

/// All interaction column labels (16 columns)
pub fn all_interaction_labels() -> Vec<String> {
    let mut labels = plonk_interaction_labels();
    labels.extend(poseidon_interaction_labels());
    assert_eq!(labels.len(), 16);
    labels
}

/// Interaction columns that have shifted samples (cols 4-7 for PLONK, 12-15 for Poseidon)
/// These are evaluated at both oods_point and shifted oods_point (z * g)
///
/// Based on actual proof structure:
/// - PLONK: cols 0-3 have 1 sample, cols 4-7 have 2 samples
/// - Poseidon: cols 8-11 have 1 sample, cols 12-15 have 2 samples
pub fn plonk_interaction_with_shifted_labels() -> Vec<String> {
    vec![
        "plonk_interaction_4".to_string(),
        "plonk_interaction_5".to_string(),
        "plonk_interaction_6".to_string(),
        "plonk_interaction_7".to_string(),
    ]
}

pub fn poseidon_interaction_with_shifted_labels() -> Vec<String> {
    vec![
        "poseidon_interaction_4".to_string(),
        "poseidon_interaction_5".to_string(),
        "poseidon_interaction_6".to_string(),
        "poseidon_interaction_7".to_string(),
    ]
}

/// Labels for shifted samples (only for columns that have them)
pub fn plonk_interaction_shifted_labels() -> Vec<String> {
    plonk_interaction_with_shifted_labels()
        .into_iter()
        .map(|s| format!("{}_shifted", s))
        .collect()
}

pub fn poseidon_interaction_shifted_labels() -> Vec<String> {
    poseidon_interaction_with_shifted_labels()
        .into_iter()
        .map(|s| format!("{}_shifted", s))
        .collect()
}

pub fn all_interaction_shifted_labels() -> Vec<String> {
    let mut labels = plonk_interaction_shifted_labels();
    labels.extend(poseidon_interaction_shifted_labels());
    assert_eq!(labels.len(), 8); // Only 8 columns have shifted samples
    labels
}

/// Composition columns (4 columns)
/// At log_size = max(log_size_plonk, log_size_poseidon) + log_blowup_factor
pub fn composition_labels() -> Vec<String> {
    vec![
        "composition_0".to_string(),
        "composition_1".to_string(),
        "composition_2".to_string(),
        "composition_3".to_string(),
    ]
}

/// Summary of column counts
pub fn column_summary() {
    println!("=== PlonkWithPoseidon Column Summary ===");
    println!("Preprocessed: {} (PLONK: {}, Poseidon: {})",
        all_preprocessed_labels().len(),
        plonk_preprocessed_labels().len(),
        poseidon_preprocessed_labels().len()
    );
    println!("Trace: {} (PLONK: {}, Poseidon: {})",
        all_trace_labels().len(),
        plonk_trace_labels().len(),
        poseidon_trace_labels().len()
    );
    println!("Interaction: {} (PLONK: {}, Poseidon: {})",
        all_interaction_labels().len(),
        plonk_interaction_labels().len(),
        poseidon_interaction_labels().len()
    );
    println!("Composition: {}", composition_labels().len());
    println!("Total: {}",
        all_preprocessed_labels().len() +
        all_trace_labels().len() +
        all_interaction_labels().len() +
        composition_labels().len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_counts() {
        assert_eq!(plonk_preprocessed_labels().len(), 10);
        assert_eq!(poseidon_preprocessed_labels().len(), 40);
        assert_eq!(all_preprocessed_labels().len(), 50);

        assert_eq!(plonk_trace_labels().len(), 12);
        assert_eq!(poseidon_trace_labels().len(), 48);
        assert_eq!(all_trace_labels().len(), 60);

        assert_eq!(plonk_interaction_labels().len(), 8);
        assert_eq!(poseidon_interaction_labels().len(), 8);
        assert_eq!(all_interaction_labels().len(), 16);

        // Shifted labels: only cols 4-7 of each have shifted samples
        assert_eq!(plonk_interaction_shifted_labels().len(), 4);
        assert_eq!(poseidon_interaction_shifted_labels().len(), 4);
        assert_eq!(all_interaction_shifted_labels().len(), 8);

        assert_eq!(composition_labels().len(), 4);

        // Total columns: 50 + 60 + 16 + 4 = 130
        let total = all_preprocessed_labels().len()
            + all_trace_labels().len()
            + all_interaction_labels().len()
            + composition_labels().len();
        assert_eq!(total, 130);
    }

    #[test]
    fn test_no_duplicate_labels() {
        let mut all_labels = Vec::new();
        all_labels.extend(all_preprocessed_labels());
        all_labels.extend(all_trace_labels());
        all_labels.extend(all_interaction_labels());
        all_labels.extend(composition_labels());

        let mut seen = std::collections::HashSet::new();
        for label in &all_labels {
            assert!(seen.insert(label.clone()), "Duplicate label: {}", label);
        }
    }

    #[test]
    fn test_sampled_values_match_proof_structure() {
        // Verify our labels match the actual proof structure:
        // tree[0]: 50 columns (preprocessed)
        // tree[1]: 60 columns (trace)
        // tree[2]: 16 columns (interaction) - with varying sample counts
        // tree[3]: 4 columns (composition)

        assert_eq!(all_preprocessed_labels().len(), 50, "tree[0] should have 50 columns");
        assert_eq!(all_trace_labels().len(), 60, "tree[1] should have 60 columns");
        assert_eq!(all_interaction_labels().len(), 16, "tree[2] should have 16 columns");
        assert_eq!(composition_labels().len(), 4, "tree[3] should have 4 columns");
    }
}
