//! PlonkWithPoseidon Fiat-Shamir Script Part 4
//!
//! This script loads all 60 trace columns and mixes them into the channel:
//! - 12 PLONK trace columns (a_val, b_val, c_val - each QM31 = 4 components)
//! - 48 Poseidon trace columns (in_state[16], intermediate_state[16], out_state[16])

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_preprocessed")?;

    // Tree[1] = Trace columns (60 total)
    // PLONK trace: 12 columns (indices 0-11)
    // Poseidon trace: 48 columns (indices 12-59)

    let mut trace_values = Vec::with_capacity(60);

    // PLONK trace columns - a_val (4 components)
    let trace_a_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][0][0])?;
    let trace_a_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][1][0])?;
    let trace_a_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][2][0])?;
    let trace_a_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][3][0])?;

    // PLONK trace columns - b_val (4 components)
    let trace_b_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][4][0])?;
    let trace_b_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][5][0])?;
    let trace_b_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][6][0])?;
    let trace_b_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][7][0])?;

    // PLONK trace columns - c_val (4 components)
    let trace_c_val_0 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][8][0])?;
    let trace_c_val_1 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][9][0])?;
    let trace_c_val_2 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][10][0])?;
    let trace_c_val_3 = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][11][0])?;

    // Compute combined a_val, b_val, c_val (QM31 from 4 components)
    let trace_a_val = &(&(&trace_a_val_0 + &trace_a_val_1.shift_by_i())
        + &trace_a_val_2.shift_by_j())
        + &trace_a_val_3.shift_by_ij();
    let trace_b_val = &(&(&trace_b_val_0 + &trace_b_val_1.shift_by_i())
        + &trace_b_val_2.shift_by_j())
        + &trace_b_val_3.shift_by_ij();
    let trace_c_val = &(&(&trace_c_val_0 + &trace_c_val_1.shift_by_i())
        + &trace_c_val_2.shift_by_j())
        + &trace_c_val_3.shift_by_ij();

    // Write PLONK trace to LDM
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

    trace_values.push(trace_a_val_0.clone());
    trace_values.push(trace_a_val_1.clone());
    trace_values.push(trace_a_val_2.clone());
    trace_values.push(trace_a_val_3.clone());
    trace_values.push(trace_b_val_0.clone());
    trace_values.push(trace_b_val_1.clone());
    trace_values.push(trace_b_val_2.clone());
    trace_values.push(trace_b_val_3.clone());
    trace_values.push(trace_c_val_0.clone());
    trace_values.push(trace_c_val_1.clone());
    trace_values.push(trace_c_val_2.clone());
    trace_values.push(trace_c_val_3.clone());

    // Poseidon trace columns - in_state[0..15]
    for i in 0..16 {
        let idx = 12 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][idx][0])?;
        ldm.write(format!("poseidon_trace_in_state_{}", i), &val)?;
        trace_values.push(val);
    }

    // Poseidon trace columns - intermediate_state[0..15]
    for i in 0..16 {
        let idx = 28 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][idx][0])?;
        ldm.write(format!("poseidon_trace_intermediate_{}", i), &val)?;
        trace_values.push(val);
    }

    // Poseidon trace columns - out_state[0..15]
    for i in 0..16 {
        let idx = 44 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[1][idx][0])?;
        ldm.write(format!("poseidon_trace_out_state_{}", i), &val)?;
        trace_values.push(val);
    }

    assert_eq!(trace_values.len(), 60, "Expected 60 trace columns");

    // Mix all trace values into channel
    channel_var.mix_felts(&trace_values);

    ldm.write("channel_var_after_trace", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
