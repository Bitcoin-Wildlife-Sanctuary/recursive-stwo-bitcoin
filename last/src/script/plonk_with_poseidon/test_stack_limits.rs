//! Test script to verify stack limits for PlonkWithPoseidon column processing
//!
//! The main concern is whether we can fit all the necessary data on Bitcoin's stack
//! when processing 130 columns instead of 28.

#[cfg(test)]
mod tests {
    use crate::script::plonk_with_poseidon::labels::*;

    /// Estimate stack usage for line coefficient computation
    /// Each QM31 value takes 4 stack elements (4 M31 components)
    /// Each line coefficient computation needs:
    /// - oods_point (x, y): 8 elements
    /// - random_coeff: 4 elements
    /// - column value: 4 elements
    /// - alpha accumulator: 4 elements
    /// - result coefficient: 8 elements (pair)
    /// Total per column: ~28 elements
    #[test]
    fn estimate_per_script_stack_usage() {
        // Bitcoin stack limit is 1000 elements
        const STACK_LIMIT: usize = 1000;

        // Base stack elements needed (always present)
        let base_elements = 100; // LDM state, table, etc.

        // Per-column processing
        let elements_per_column = 28;

        // How many columns can we process per script?
        let available = STACK_LIMIT - base_elements;
        let max_columns_per_script = available / elements_per_column;

        println!("Stack limit: {}", STACK_LIMIT);
        println!("Base elements: {}", base_elements);
        println!("Elements per column: {}", elements_per_column);
        println!("Max columns per script: {}", max_columns_per_script);

        // Current design processes 2 columns per script
        // This should be safe
        assert!(max_columns_per_script >= 2, "Cannot process 2 columns per script!");

        // We could potentially process more columns per script to reduce script count
        // But 2 is a safe conservative choice
    }

    /// Calculate how many scripts we need for line coefficients
    #[test]
    fn calculate_line_coeff_scripts() {
        let columns_per_script = 2;

        // Original columns at log_size_plonk
        let plonk_preprocessed = plonk_preprocessed_labels().len(); // 10
        let plonk_trace = plonk_trace_labels().len(); // 12
        let plonk_interaction = plonk_interaction_labels().len(); // 8
        let plonk_total = plonk_preprocessed + plonk_trace + plonk_interaction; // 30

        // Poseidon columns at log_size_poseidon
        let poseidon_preprocessed = poseidon_preprocessed_labels().len(); // 40
        let poseidon_trace = poseidon_trace_labels().len(); // 48
        let poseidon_interaction = poseidon_interaction_labels().len(); // 8
        let poseidon_total = poseidon_preprocessed + poseidon_trace + poseidon_interaction; // 96

        // Shifted interaction columns (8 total, need separate handling)
        let shifted_total = all_interaction_shifted_labels().len(); // 8

        // Composition columns (at max log_size)
        let composition_total = composition_labels().len(); // 4

        println!("\n=== Line Coefficient Scripts Needed ===");
        println!("PLONK columns (log_size_plonk): {} -> {} scripts",
            plonk_total, (plonk_total + columns_per_script - 1) / columns_per_script);
        println!("Poseidon columns (log_size_poseidon): {} -> {} scripts",
            poseidon_total, (poseidon_total + columns_per_script - 1) / columns_per_script);
        println!("Shifted interaction: {} -> {} scripts",
            shifted_total, (shifted_total + columns_per_script - 1) / columns_per_script);
        println!("Composition: {} -> {} scripts",
            composition_total, (composition_total + columns_per_script - 1) / columns_per_script);

        let total_scripts =
            (plonk_total + columns_per_script - 1) / columns_per_script +
            (poseidon_total + columns_per_script - 1) / columns_per_script +
            (shifted_total + columns_per_script - 1) / columns_per_script +
            (composition_total + columns_per_script - 1) / columns_per_script;

        println!("\nTotal line coefficient scripts: {}", total_scripts);
        println!("(Current PlonkWithoutPoseidon: 16 scripts)");
        println!("Increase factor: {:.1}x", total_scripts as f64 / 16.0);

        // Verify we're in a reasonable range
        assert!(total_scripts < 100, "Too many scripts!");
    }

    /// Estimate total script count
    #[test]
    fn estimate_total_script_count() {
        println!("\n=== Total Script Count Estimate ===\n");

        // Global scripts (run once)
        let fiat_shamir_scripts = 2; // Similar to current
        let composition_scripts = 4; // May need more for dual constraints
        let coset_vanishing_scripts = 3;
        let logup_scripts = 2; // One for PLONK, one for Poseidon
        let point_shift_scripts = 1;

        // Line coefficient scripts (calculated above)
        let line_coeff_scripts = 71; // From calculation above

        let global_total = fiat_shamir_scripts + composition_scripts +
            coset_vanishing_scripts + logup_scripts + point_shift_scripts + line_coeff_scripts;

        println!("Global scripts: {}", global_total);
        println!("  Fiat-Shamir: {}", fiat_shamir_scripts);
        println!("  Composition: {}", composition_scripts);
        println!("  Coset vanishing: {}", coset_vanishing_scripts);
        println!("  Logup: {}", logup_scripts);
        println!("  Point shift: {}", point_shift_scripts);
        println!("  Line coefficients: {}", line_coeff_scripts);

        // Per-query scripts
        // Current: 13 scripts per query
        // With PlonkWithPoseidon: need to verify more columns
        let n_queries = 8;
        let domain_point_scripts = 1;
        let numerator_scripts = 10; // More columns to verify
        let fri_decommit_scripts = 1;
        let folding_scripts = 4;
        let clear_scripts = 1;
        let per_query_total = domain_point_scripts + numerator_scripts +
            fri_decommit_scripts + folding_scripts + clear_scripts;

        println!("\nPer-query scripts: {} × {} queries = {}",
            per_query_total, n_queries, per_query_total * n_queries);

        // Final script
        let final_scripts = 1;

        let total = global_total + per_query_total * n_queries + final_scripts;
        println!("\nTotal scripts: {}", total);
        println!("(Current PlonkWithoutPoseidon: 131 scripts)");
        println!("Increase factor: {:.1}x", total as f64 / 131.0);
    }
}
