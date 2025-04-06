use crate::script::hints::LastFiatShamirHints;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::composition::PointEvaluationAccumulatorBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::pow::verify_pow;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

pub fn generate_cs(
    fiat_shamir_hints: &LastFiatShamirHints<Sha256MerkleChannel>,
    proof: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    config: PcsConfig,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_z_and_alpha")?;
    let input_sum: QM31Bar = ldm.read("input_acc_sum_39")?;

    // Update the channel with checksum
    let plonk_total_sum = QM31Bar::new_hint(&cs, fiat_shamir_hints.plonk_total_sum)?;
    ldm.write("plonk_total_sum", &plonk_total_sum)?;

    let expected_zero = &input_sum + &plonk_total_sum;
    expected_zero.is_zero();

    channel_var.mix_felts(&[plonk_total_sum]);

    // Interaction trace.
    let interaction_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[2].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&interaction_commitment_var);

    let random_coeff = channel_var.draw_felt();
    ldm.write("random_coeff", &random_coeff)?;

    // Read composition polynomial commitment.
    let composition_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[3].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&composition_commitment_var);

    // Draw OODS point.
    let oods_t = channel_var.draw_felt();
    ldm.write("oods_t", &oods_t)?;

    // Load the preprocessed columns
    let preprocessed_a_wire = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][0][0])?;
    let preprocessed_b_wire = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][1][0])?;
    let preprocessed_c_wire = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][2][0])?;
    let preprocessed_op1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][3][0])?;
    let preprocessed_op2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][4][0])?;
    let preprocessed_op3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][5][0])?;
    let preprocessed_op4 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][6][0])?;
    let preprocessed_mult_c = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][7][0])?;

    ldm.write("preprocessed_a_wire", &preprocessed_a_wire)?;
    ldm.write("preprocessed_b_wire", &preprocessed_b_wire)?;
    ldm.write("preprocessed_c_wire", &preprocessed_c_wire)?;
    ldm.write("preprocessed_op1", &preprocessed_op1)?;
    ldm.write("preprocessed_op2", &preprocessed_op2)?;
    ldm.write("preprocessed_op3", &preprocessed_op3)?;
    ldm.write("preprocessed_op4", &preprocessed_op4)?;
    ldm.write("preprocessed_mult_c", &preprocessed_mult_c)?;

    channel_var.mix_felts(&[
        preprocessed_a_wire.clone(),
        preprocessed_b_wire.clone(),
        preprocessed_c_wire.clone(),
        preprocessed_op1.clone(),
        preprocessed_op2.clone(),
        preprocessed_op3.clone(),
        preprocessed_op4.clone(),
        preprocessed_mult_c.clone(),
    ]);

    // Load the trace columns
    let trace_a_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][0][0])?;
    let trace_a_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][1][0])?;
    let trace_a_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][2][0])?;
    let trace_a_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][3][0])?;

    let trace_b_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][4][0])?;
    let trace_b_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][5][0])?;
    let trace_b_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][6][0])?;
    let trace_b_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][7][0])?;

    let trace_c_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][8][0])?;
    let trace_c_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][9][0])?;
    let trace_c_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][10][0])?;
    let trace_c_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][11][0])?;

    let trace_a_val = &(&(&trace_a_val_0 + &trace_a_val_1.shift_by_i()) + &trace_a_val_2.shift_by_j())
        + &trace_a_val_3.shift_by_ij();
    let trace_b_val = &(&(&trace_b_val_0 + &trace_b_val_1.shift_by_i()) + &trace_b_val_2.shift_by_j())
        + &trace_b_val_3.shift_by_ij();
    let trace_c_val = &(&(&trace_c_val_0 + &trace_c_val_1.shift_by_i()) + &trace_c_val_2.shift_by_j())
        + &trace_c_val_3.shift_by_ij();

    ldm.write("trace_a_val_0", &trace_a_val_0)?;
    ldm.write("trace_a_val_1", &trace_a_val_1)?;
    ldm.write("trace_a_val_2", &trace_a_val_2)?;
    ldm.write("trace_a_val_3", &trace_a_val_3)?;
    ldm.write("trace_b_val_0", &trace_b_val_0)?;
    ldm.write("trace_b_val_1", &trace_b_val_1)?;
    ldm.write("trace_b_val_2", &trace_b_val_2)?;
    ldm.write("trace_b_val_3", &trace_b_val_3)?;
    ldm.write("trace_c_val_0", &trace_c_val_0)?;
    ldm.write("trace_c_val_1", &trace_c_val_1)?;
    ldm.write("trace_c_val_2", &trace_c_val_2)?;
    ldm.write("trace_c_val_3", &trace_c_val_3)?;
    ldm.write("trace_a_val", &trace_a_val)?;
    ldm.write("trace_b_val", &trace_b_val)?;
    ldm.write("trace_c_val", &trace_c_val)?;

    channel_var.mix_felts(&[
        trace_a_val_0.clone(),
        trace_a_val_1.clone(),
        trace_a_val_2.clone(),
        trace_a_val_3.clone(),
        trace_b_val_0.clone(),
        trace_b_val_1.clone(),
        trace_b_val_2.clone(),
        trace_b_val_3.clone(),
        trace_c_val_0.clone(),
        trace_c_val_1.clone(),
        trace_c_val_2.clone(),
        trace_c_val_3.clone(),
    ]);

    let interaction_prev_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][0][0])?;
    let interaction_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][0][1])?;

    let interaction_prev_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][1][0])?;
    let interaction_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][1][1])?;

    let interaction_prev_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][2][0])?;
    let interaction_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][2][1])?;

    let interaction_prev_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][3][0])?;
    let interaction_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][3][1])?;

    let interaction_prev = &(&(&interaction_prev_0 + &interaction_prev_1.shift_by_i())
        + &interaction_prev_2.shift_by_j())
        + &interaction_prev_3.shift_by_ij();
    let interaction = &(&(&interaction_0 + &interaction_1.shift_by_i())
        + &interaction_2.shift_by_j())
        + &interaction_3.shift_by_ij();

    ldm.write("interaction_prev_0", &interaction_prev_0)?;
    ldm.write("interaction_prev_1", &interaction_prev_1)?;
    ldm.write("interaction_prev_2", &interaction_prev_2)?;
    ldm.write("interaction_prev_3", &interaction_prev_3)?;
    ldm.write("interaction_0", &interaction_0)?;
    ldm.write("interaction_1", &interaction_1)?;
    ldm.write("interaction_2", &interaction_2)?;
    ldm.write("interaction_3", &interaction_3)?;
    ldm.write("interaction_prev", &interaction_prev)?;
    ldm.write("interaction", &interaction)?;

    channel_var.mix_felts(&[
        interaction_prev_0.clone(),
        interaction_0.clone(),
        interaction_prev_1.clone(),
        interaction_1.clone(),
        interaction_prev_2.clone(),
        interaction_2.clone(),
        interaction_prev_3.clone(),
        interaction_3.clone(),
    ]);

    let composition_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[3][0][0])?;
    let composition_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[3][1][0])?;
    let composition_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[3][2][0])?;
    let composition_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[3][3][0])?;

    let composition = &(&(&composition_0 + &composition_1.shift_by_i())
        + &composition_2.shift_by_j())
        + &composition_3.shift_by_ij();
    ldm.write("composition_0", &composition_0)?;
    ldm.write("composition_1", &composition_1)?;
    ldm.write("composition_2", &composition_2)?;
    ldm.write("composition_3", &composition_3)?;
    ldm.write("composition", &composition)?;

    channel_var.mix_felts(&[
        composition_0.clone(),
        composition_1.clone(),
        composition_2.clone(),
        composition_3.clone(),
    ]);

    let after_sampled_values_random_coeff = channel_var.draw_felt();
    ldm.write(
        "after_sampled_values_random_coeff",
        &after_sampled_values_random_coeff,
    )?;

    let first_layer_commitment =
        Sha256HashBar::new_hint(&cs, proof.stark_proof.fri_proof.first_layer.commitment)?;
    channel_var.mix_root(&first_layer_commitment);
    ldm.write("first_layer_commitment", &first_layer_commitment)?;

    let first_layer_alpha = channel_var.draw_felt();
    ldm.write("first_layer_alpha", &first_layer_alpha)?;

    assert_eq!(proof.stark_proof.fri_proof.inner_layers.len(), 18);
    for i in 0..18 {
        let inner_layer_commitment =
            Sha256HashBar::new_hint(&cs, proof.stark_proof.fri_proof.inner_layers[i].commitment)?;
        channel_var.mix_root(&inner_layer_commitment);
        ldm.write(
            format!("inner_layer_commitment_{}", i),
            &inner_layer_commitment,
        )?;

        let inner_layer_alpha = channel_var.draw_felt();
        ldm.write(format!("inner_layer_alpha_{}", i), &inner_layer_alpha)?;
    }

    assert_eq!(proof.stark_proof.fri_proof.last_layer_poly.log_size, 0);
    let last_layer_poly =
        QM31Bar::new_hint(&cs, proof.stark_proof.fri_proof.last_layer_poly.coeffs[0])?;
    ldm.write("last_layer_poly", &last_layer_poly)?;
    channel_var.mix_felts(&[last_layer_poly]);

    let nonce = &StrBar::new_hint(&cs, proof.stark_proof.proof_of_work.to_le_bytes().to_vec())?
        + &StrBar::new_constant(&cs, [0x0; 24].to_vec())?;
    channel_var.mix_str(&nonce);

    verify_pow(&channel_var, config.pow_bits as usize)?;

    assert_eq!(config.fri_config.n_queries, 8);
    let raw_queries_felt_1 = channel_var.draw_felt();
    let raw_queries_felt_2 = channel_var.draw_felt();

    ldm.write("raw_queries_felt_1", &raw_queries_felt_1)?;
    ldm.write("raw_queries_felt_2", &raw_queries_felt_2)?;

    let table = TableBar::new_constant(&cs, ())?;

    let random_coeff: QM31Bar = ldm.read("random_coeff")?;

    let mut eval_acc = PointEvaluationAccumulatorBar::new(&random_coeff)?;
    let is_pow5 = preprocessed_op2.clone();

    let mut a_val_0_pow4 = &trace_a_val_0 * (&table, &trace_a_val_0);
    a_val_0_pow4 = &a_val_0_pow4 * (&table, &a_val_0_pow4);

    let mut a_val_1_pow4 = &trace_a_val_1 * (&table, &trace_a_val_1);
    a_val_1_pow4 = &a_val_1_pow4 * (&table, &a_val_1_pow4);

    eval_acc.accumulate(
        &table,
        &(&(&a_val_0_pow4 - &trace_b_val_0) * (&table, &is_pow5)),
    );
    eval_acc.accumulate(
        &table,
        &(&(&a_val_1_pow4 - &trace_b_val_1) * (&table, &is_pow5)),
    );

    ldm.write("eval_acc_accumulation_part3", &eval_acc.accumulation)?;

    ldm.save()?;
    Ok(cs)
}
