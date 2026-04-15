//! PlonkWithPoseidon Point Shift Script Part 11
//!
//! This script:
//! 1. Verifies the PLONK logup constraint using interaction columns
//! 2. Verifies the composition polynomial matches expected value
//! 3. Initializes line coefficient randomizers for different log sizes
//! 4. Computes the shifted OODS point for interaction columns

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::circle::CirclePointQM31Bar;
use recursive_stwo_primitives::composition::PointEvaluationAccumulatorBar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::LineCoeffRandomizerBar;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;

    // Load PLONK interaction values
    // Cols 4-7 have shifted samples (at oods_point * g)
    let plonk_interaction_4: QM31Bar = ldm.read("plonk_interaction_4")?;
    let plonk_interaction_5: QM31Bar = ldm.read("plonk_interaction_5")?;
    let plonk_interaction_6: QM31Bar = ldm.read("plonk_interaction_6")?;
    let plonk_interaction_7: QM31Bar = ldm.read("plonk_interaction_7")?;

    let plonk_interaction_4_shifted: QM31Bar = ldm.read("plonk_interaction_4_shifted")?;
    let plonk_interaction_5_shifted: QM31Bar = ldm.read("plonk_interaction_5_shifted")?;
    let plonk_interaction_6_shifted: QM31Bar = ldm.read("plonk_interaction_6_shifted")?;
    let plonk_interaction_7_shifted: QM31Bar = ldm.read("plonk_interaction_7_shifted")?;

    // Combine into QM31 values (current and previous)
    let interaction = &(&(&plonk_interaction_4 + &plonk_interaction_5.shift_by_i())
        + &plonk_interaction_6.shift_by_j())
        + &plonk_interaction_7.shift_by_ij();
    let interaction_prev = &(&(&plonk_interaction_4_shifted + &plonk_interaction_5_shifted.shift_by_i())
        + &plonk_interaction_6_shifted.shift_by_j())
        + &plonk_interaction_7_shifted.shift_by_ij();

    let diff = &interaction - &interaction_prev;

    // Load total_sums and compute cumsum shift
    let plonk_total_sum: QM31Bar = ldm.read("plonk_total_sum")?;
    let shift = M31::from_u32_unchecked(1 << proof.stmt0.log_size_plonk).inverse();
    let cumsum_shift: QM31Bar = &plonk_total_sum * (&table, &M31Bar::new_constant(&cs, shift)?);
    let fixed_diff = &diff + &cumsum_shift;

    // Load relation values computed in part10
    let relation_num: QM31Bar = ldm.read("plonk_relation_num")?;
    let relation_denom: QM31Bar = ldm.read("plonk_relation_denom")?;

    // Load random_coeff for accumulator (placeholder for now)
    let random_coeff: QM31Bar = ldm.read("random_coeff")?;

    // Start accumulator (this will be accumulated with composition constraints)
    let mut eval_acc = PointEvaluationAccumulatorBar::new(&random_coeff)?;

    // Verify: diff * denom - num = 0 (logup constraint)
    eval_acc.accumulate(
        &table,
        &(&(&fixed_diff * (&table, &relation_denom)) - &relation_num),
    );

    ldm.write("eval_acc_after_logup", &eval_acc.accumulation)?;

    // Initialize line coefficient randomizers
    let after_sampled_values_random_coeff: QM31Bar =
        ldm.read("after_sampled_values_random_coeff")?;

    // Randomizer for log_size 24 columns (preprocessed, trace, interaction)
    let line_coeff_randomizer_24 = LineCoeffRandomizerBar::new(&after_sampled_values_random_coeff)?;
    ldm.write(
        "line_coeff_randomizer_24_alpha_0",
        &line_coeff_randomizer_24.alpha,
    )?;

    // Randomizer for log_size 27 columns (composition)
    let line_coeff_randomizer_27 = LineCoeffRandomizerBar::new(&after_sampled_values_random_coeff)?;
    ldm.write(
        "line_coeff_randomizer_27_alpha_0",
        &line_coeff_randomizer_27.alpha,
    )?;

    // Compute shifted OODS point for interaction columns
    let oods_x: QM31Bar = ldm.read("oods_x")?;
    let oods_y: QM31Bar = ldm.read("oods_y")?;
    let oods_point = CirclePointQM31Bar {
        x: oods_x,
        y: oods_y,
    };

    // Shift point by negative coset step
    let shift_point = CanonicCoset::new(proof.stmt0.log_size_plonk)
        .step()
        .mul_signed(-1);
    let oods_shifted_point = &oods_point + (&table, &shift_point);

    ldm.write("oods_shifted_x", &oods_shifted_point.x)?;
    ldm.write("oods_shifted_y", &oods_shifted_point.y)?;

    ldm.save()?;
    Ok(cs)
}
