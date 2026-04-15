//! Per-query Bitcoin scripts for PlonkWithPoseidon verification
//!
//! These scripts run once per FRI query (8 queries total).
//! They handle:
//! - Domain point computation
//! - Column numerator computation (decommitment + line coefficient application)
//! - FRI decommitment
//! - FRI folding
//!
//! Script sequence per query:
//! - part1_domain_point: Domain point computation, composition decommit
//! - part2_preprocessed: Preprocessed decommit, PLONK prep numerators
//! - part3_poseidon_prep: Poseidon prep numerators
//! - part4_trace: Trace decommit, PLONK trace numerators
//! - part5_poseidon_trace: Poseidon trace numerators
//! - part6_interaction: Interaction decommit and numerators
//! - part7_combine: Combine all numerators into query answer
//! - part8_fri_first: FRI first layer folding
//! - part9_folding: FRI inner layers 26->22
//! - part10_folding: FRI inner layers 22->18 (via part9_folding)
//! - part11_folding: FRI inner layers 18->14 (via part9_folding)
//! - part12_folding: FRI inner layers 14->final (via part9_folding)
//! - part13_verify: Verify final value against last layer polynomial
//! - part14_clear: Clear per-query state

pub mod part1_domain_point;
pub mod part2_preprocessed;
pub mod part3_poseidon_prep;
pub mod part4_trace;
pub mod part5_poseidon_trace;
pub mod part6_interaction;
pub mod part7_combine;
pub mod part8_fri_first;
pub mod part9_folding;
pub mod part13_verify;
pub mod part14_clear;

#[cfg(test)]
mod tests {
    use crate::script::plonk_with_poseidon::decommit::PwpDecommitHints;
    use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
    use recursive_stwo_bitcoin_dsl::compiler::Compiler;
    use recursive_stwo_bitcoin_dsl::ldm::LDM;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

    fn setup_ldm() -> (LDM, PwpFiatShamirHints<Sha256MerkleChannel>, PlonkWithPoseidonProof<Sha256MerkleHasher>, PcsConfig) {
        let proof_bytes = std::fs::read("../data/poseidon_accelerated_proof.bin")
            .expect("Failed to load proof");
        let proof: PlonkWithPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(&proof_bytes).unwrap();

        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };
        let inputs: Vec<(usize, stwo_prover::core::fields::qm31::QM31)> = vec![];

        let fiat_shamir_hints =
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config.clone(), &inputs);

        let mut ldm = LDM::new();

        // Run global scripts
        let cs = crate::script::plonk_with_poseidon::global::part1_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part2_fiat_shamir::generate_cs(&fiat_shamir_hints, &proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part3_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part4_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part5_fiat_shamir::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part6_fiat_shamir::generate_cs(&proof, config.clone(), &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part7_coset_vanishing::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part10_logup::generate_cs(&mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();
        let cs = crate::script::plonk_with_poseidon::global::part11_point_shift::generate_cs(&proof, &mut ldm).unwrap();
        let _ = Compiler::compile(cs).unwrap();

        // Run line coefficient scripts
        use crate::script::plonk_with_poseidon::global::line_coeffs::*;
        let shifted_labels = generate_shifted_interaction_labels();
        let original_labels = generate_original_logsize_24_labels();
        let composition_labels = generate_composition_labels();
        let (shifted_count, original_count, composition_count, _) = count_line_coeff_scripts();

        for counter in 0..shifted_count {
            let cs = generate_shifted_cs(&mut ldm, counter, &shifted_labels).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }
        for counter in 0..original_count {
            let cs = generate_original_24_cs(&mut ldm, counter, &original_labels, shifted_count).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }
        for counter in 0..composition_count {
            let cs = generate_composition_cs(&mut ldm, counter, &composition_labels).unwrap();
            let _ = Compiler::compile(cs).unwrap();
        }

        (ldm, fiat_shamir_hints, proof, config)
    }

    /// Integration test: Run parts 1-7 in sequence for query 0
    #[test]
    fn test_per_query_parts_1_to_7() {
        let (mut ldm, fiat_shamir_hints, proof, _config) = setup_ldm();
        let mut ldm_per_query = LDM::new();

        println!("=== Running per-query scripts for query 0 ===\n");

        // Part 1: Domain point computation + composition decommit
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
        let cs = super::part1_domain_point::generate_cs(
            0, 24, 27,
            &decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 1 (domain_point): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 2: Preprocessed decommit + PLONK prep numerators
        let decommit_preprocessed_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 0);
        let cs = super::part2_preprocessed::generate_cs(
            0,
            &decommit_preprocessed_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 2 (preprocessed): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 3: Poseidon prep numerators
        let cs = super::part3_poseidon_prep::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 3 (poseidon_prep): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 4: Trace decommit + PLONK trace numerators
        let decommit_trace_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 1);
        let cs = super::part4_trace::generate_cs(
            0,
            &decommit_trace_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 4 (trace): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 5: Poseidon trace numerators
        let cs = super::part5_poseidon_trace::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 5 (poseidon_trace): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 6: Interaction decommit + numerators
        let decommit_interaction_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 2);
        let cs = super::part6_interaction::generate_cs(
            0,
            &decommit_interaction_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 6 (interaction): {} bytes, {} hints", program.script.len(), program.hint.len());

        // Part 7: Combine numerators into query answer
        let cs = super::part7_combine::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 7 (combine): {} bytes, {} hints", program.script.len(), program.hint.len());

        println!("\n=== All parts 1-7 completed successfully! ===");
    }

    /// Integration test: Run all parts 1-13 in sequence for query 0
    /// This includes FRI folding and final verification
    #[test]
    fn test_per_query_complete() {
        use crate::script::plonk_with_poseidon::answer::PwpAnswerHints;
        use crate::script::plonk_with_poseidon::fri_hints::PwpFriHints;
        use stwo_prover::core::fields::qm31::SecureField;

        let (mut ldm, fiat_shamir_hints, proof, _config) = setup_ldm();
        let mut ldm_per_query = LDM::new();

        println!("=== Running COMPLETE per-query scripts for query 0 ===\n");

        // Compute actual FRI answers
        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        // Combined FRI answer = answer_24 + answer_27
        let combined_answers: Vec<SecureField> = (0..8)
            .map(|i| answer_hints.fri_answers[0][i] + answer_hints.fri_answers[1][i])
            .collect();

        let fri_hints = PwpFriHints::compute(&combined_answers, &fiat_shamir_hints, &proof);

        // === Parts 1-7: Decommitment and numerator computation ===

        // Part 1: Domain point computation + composition decommit
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
        let cs = super::part1_domain_point::generate_cs(
            0, 24, 27,
            &decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 1 (domain_point): {} bytes", program.script.len());

        // Part 2: Preprocessed decommit + PLONK prep numerators
        let decommit_preprocessed_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 0);
        let cs = super::part2_preprocessed::generate_cs(
            0,
            &decommit_preprocessed_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 2 (preprocessed): {} bytes", program.script.len());

        // Part 3: Poseidon prep numerators
        let cs = super::part3_poseidon_prep::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 3 (poseidon_prep): {} bytes", program.script.len());

        // Part 4: Trace decommit + PLONK trace numerators
        let decommit_trace_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 1);
        let cs = super::part4_trace::generate_cs(
            0,
            &decommit_trace_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 4 (trace): {} bytes", program.script.len());

        // Part 5: Poseidon trace numerators
        let cs = super::part5_poseidon_trace::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 5 (poseidon_trace): {} bytes", program.script.len());

        // Part 6: Interaction decommit + numerators
        let decommit_interaction_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 2);
        let cs = super::part6_interaction::generate_cs(
            0,
            &decommit_interaction_hints,
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 6 (interaction): {} bytes", program.script.len());

        // Part 7: Combine numerators into query answer
        let cs = super::part7_combine::generate_cs(
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 7 (combine): {} bytes", program.script.len());

        // === Parts 8-11: FRI folding ===

        // Part 8: FRI first layer (27 -> 26)
        let cs = super::part8_fri_first::generate_cs(
            &fri_hints.query_hints[0],
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 8 (fri_first): {} bytes", program.script.len());

        // Part 9: FRI inner layers 26->22
        let cs = super::part9_folding::generate_part9_cs(
            &fri_hints.query_hints[0],
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 9 (fold 26->22): {} bytes", program.script.len());

        // Part 10: FRI inner layers 22->18
        let cs = super::part9_folding::generate_part10_cs(
            &fri_hints.query_hints[0],
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 10 (fold 22->18): {} bytes", program.script.len());

        // Part 11: FRI inner layers 18->16
        let cs = super::part9_folding::generate_part11_cs(
            &fri_hints.query_hints[0],
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 11 (fold 18->16): {} bytes", program.script.len());

        // === Part 13: Final verification ===
        let cs = super::part13_verify::generate_cs(
            0,
            &fri_hints.query_hints[0],
            &mut ldm,
            &mut ldm_per_query,
        ).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!("Part 13 (verify): {} bytes", program.script.len());

        println!("\n=== All parts 1-13 completed successfully! ===");
        println!("Using actual FRI answers computed from proof");
        println!("Final layer log_size: {}", fri_hints.final_log_size);
    }

    /// End-to-end verification: Run all parts for all 8 queries
    #[test]
    fn test_all_queries_e2e() {
        use crate::script::plonk_with_poseidon::answer::PwpAnswerHints;
        use crate::script::plonk_with_poseidon::fri_hints::PwpFriHints;
        use stwo_prover::core::fields::qm31::SecureField;

        let (mut ldm, fiat_shamir_hints, proof, _config) = setup_ldm();

        println!("=== Running E2E verification for ALL 8 QUERIES ===\n");

        // Compute actual FRI answers
        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        // Combined FRI answer = answer_24 + answer_27
        let combined_answers: Vec<SecureField> = (0..8)
            .map(|i| answer_hints.fri_answers[0][i] + answer_hints.fri_answers[1][i])
            .collect();

        let fri_hints = PwpFriHints::compute(&combined_answers, &fiat_shamir_hints, &proof);

        // Compute decommitment hints once (they're the same for all queries, just indexed differently)
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
        let decommit_preprocessed_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 0);
        let decommit_trace_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 1);
        let decommit_interaction_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 2);

        let mut total_script_size = 0usize;

        for query_idx in 0..8 {
            let mut ldm_per_query = LDM::new();
            let mut query_size = 0usize;

            // Part 1: Domain point + composition decommit
            let cs = super::part1_domain_point::generate_cs(
                query_idx, 24, 27,
                &decommit_composition_hints,
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 2: Preprocessed decommit
            let cs = super::part2_preprocessed::generate_cs(
                query_idx,
                &decommit_preprocessed_hints,
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 3: Poseidon prep numerators
            let cs = super::part3_poseidon_prep::generate_cs(
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 4: Trace decommit
            let cs = super::part4_trace::generate_cs(
                query_idx,
                &decommit_trace_hints,
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 5: Poseidon trace numerators
            let cs = super::part5_poseidon_trace::generate_cs(
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 6: Interaction decommit
            let cs = super::part6_interaction::generate_cs(
                query_idx,
                &decommit_interaction_hints,
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 7: Combine numerators
            let cs = super::part7_combine::generate_cs(
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 8: FRI first layer
            let cs = super::part8_fri_first::generate_cs(
                &fri_hints.query_hints[query_idx],
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 9: FRI fold 26->22
            let cs = super::part9_folding::generate_part9_cs(
                &fri_hints.query_hints[query_idx],
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 10: FRI fold 22->18
            let cs = super::part9_folding::generate_part10_cs(
                &fri_hints.query_hints[query_idx],
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 11: FRI fold 18->16
            let cs = super::part9_folding::generate_part11_cs(
                &fri_hints.query_hints[query_idx],
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            // Part 13: Final verification
            let cs = super::part13_verify::generate_cs(
                query_idx,
                &fri_hints.query_hints[query_idx],
                &mut ldm,
                &mut ldm_per_query,
            ).unwrap();
            query_size += Compiler::compile(cs).unwrap().script.len();

            println!("Query {}: {} KB", query_idx, query_size / 1024);
            total_script_size += query_size;
        }

        println!("\n=== E2E Summary ===");
        println!("Total per-query scripts: {} MB", total_script_size as f64 / 1024.0 / 1024.0);
        println!("All 8 queries completed successfully!");
    }

    /// Summary test: Calculate total script size for PlonkWithPoseidon verification
    #[test]
    fn test_complete_verification_summary() {
        use crate::script::plonk_with_poseidon::answer::PwpAnswerHints;
        use crate::script::plonk_with_poseidon::fri_hints::PwpFriHints;
        use stwo_prover::core::fields::qm31::SecureField;

        let (mut ldm, fiat_shamir_hints, proof, _config) = setup_ldm();

        // Compute actual FRI answers
        let answer_hints =
            PwpAnswerHints::<Sha256MerkleChannel>::compute(&fiat_shamir_hints, &proof);

        // Combined FRI answer = answer_24 + answer_27
        let combined_answers: Vec<SecureField> = (0..8)
            .map(|i| answer_hints.fri_answers[0][i] + answer_hints.fri_answers[1][i])
            .collect();

        let fri_hints = PwpFriHints::compute(&combined_answers, &fiat_shamir_hints, &proof);

        println!("\n=== PlonkWithPoseidon Verification Script Summary ===\n");

        // Calculate sizes for one query by running sequentially
        let mut ldm_per_query = LDM::new();
        let mut per_query_sizes: Vec<(&str, usize)> = Vec::new();

        // Part 1
        let decommit_composition_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
        let cs = super::part1_domain_point::generate_cs(0, 24, 27, &decommit_composition_hints, &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 1: Domain point + composition", Compiler::compile(cs).unwrap().script.len()));

        // Part 2
        let decommit_preprocessed_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 0);
        let cs = super::part2_preprocessed::generate_cs(0, &decommit_preprocessed_hints, &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 2: Preprocessed decommit", Compiler::compile(cs).unwrap().script.len()));

        // Part 3
        let cs = super::part3_poseidon_prep::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 3: Poseidon prep numerators", Compiler::compile(cs).unwrap().script.len()));

        // Part 4
        let decommit_trace_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 1);
        let cs = super::part4_trace::generate_cs(0, &decommit_trace_hints, &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 4: Trace decommit", Compiler::compile(cs).unwrap().script.len()));

        // Part 5
        let cs = super::part5_poseidon_trace::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 5: Poseidon trace numerators", Compiler::compile(cs).unwrap().script.len()));

        // Part 6
        let decommit_interaction_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, 2);
        let cs = super::part6_interaction::generate_cs(0, &decommit_interaction_hints, &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 6: Interaction decommit", Compiler::compile(cs).unwrap().script.len()));

        // Part 7
        let cs = super::part7_combine::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 7: Combine numerators", Compiler::compile(cs).unwrap().script.len()));

        // Part 8
        let cs = super::part8_fri_first::generate_cs(&fri_hints.query_hints[0], &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 8: FRI first layer", Compiler::compile(cs).unwrap().script.len()));

        // Part 9
        let cs = super::part9_folding::generate_part9_cs(&fri_hints.query_hints[0], &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 9: FRI fold 26->22", Compiler::compile(cs).unwrap().script.len()));

        // Part 10
        let cs = super::part9_folding::generate_part10_cs(&fri_hints.query_hints[0], &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 10: FRI fold 22->18", Compiler::compile(cs).unwrap().script.len()));

        // Part 11
        let cs = super::part9_folding::generate_part11_cs(&fri_hints.query_hints[0], &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 11: FRI fold 18->16", Compiler::compile(cs).unwrap().script.len()));

        // Part 13
        let cs = super::part13_verify::generate_cs(0, &fri_hints.query_hints[0], &mut ldm, &mut ldm_per_query).unwrap();
        per_query_sizes.push(("Part 13: Final verify", Compiler::compile(cs).unwrap().script.len()));

        // Calculate totals
        let per_query_total: usize = per_query_sizes.iter().map(|(_, s)| *s).sum();

        // Print per-query breakdown
        println!("Per-Query Scripts (12 scripts per query):");
        for (name, size) in &per_query_sizes {
            println!("  {}: {:>8} bytes ({:.1} KB)", name, size, *size as f64 / 1024.0);
        }
        println!("  -----------------------------------");
        println!("  Per-query total: {:>8} bytes ({:.1} KB)", per_query_total, per_query_total as f64 / 1024.0);

        // Total for all queries
        let n_queries = 8;  // PlonkWithPoseidon uses 8 FRI queries
        let all_queries_total = per_query_total * n_queries;
        println!("\nAll {} queries total: {} bytes ({:.2} MB)",
            n_queries, all_queries_total, all_queries_total as f64 / 1024.0 / 1024.0);

        // Global scripts (from test_complete_global_scripts_summary)
        let global_total = 3_408_247;
        println!("\nGlobal scripts total: {} bytes ({:.2} MB)",
            global_total, global_total as f64 / 1024.0 / 1024.0);

        // Grand total
        let grand_total = all_queries_total + global_total;
        println!("\n=== GRAND TOTAL: {} bytes ({:.2} MB) ===",
            grand_total, grand_total as f64 / 1024.0 / 1024.0);

        println!("\nScript count:");
        println!("  Global: 80 scripts");
        println!("  Per-query: 12 scripts x 8 queries = 96 scripts");
        println!("  Total: 176 scripts");
    }
}
