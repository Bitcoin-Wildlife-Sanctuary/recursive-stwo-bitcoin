//! PlonkWithPoseidon Fiat-Shamir Script Part 5
//!
//! This script loads interaction columns (16) and composition columns (4), then mixes them:
//! - 8 PLONK interaction columns (cols 0-3 have 1 sample, cols 4-7 have 2 samples)
//! - 8 Poseidon interaction columns (cols 0-3 have 1 sample, cols 4-7 have 2 samples)
//! - 4 composition columns

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

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_trace")?;

    // Tree[2] = Interaction columns (16 total)
    // PLONK interaction: 8 columns (indices 0-7)
    //   - cols 0-3: 1 sample each (at oods_point)
    //   - cols 4-7: 2 samples each (at oods_point and shifted)
    // Poseidon interaction: 8 columns (indices 8-15)
    //   - cols 8-11: 1 sample each
    //   - cols 12-15: 2 samples each

    let mut interaction_values = Vec::new();

    // PLONK interaction columns 0-3 (1 sample each)
    for i in 0..4 {
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][0])?;
        ldm.write(format!("plonk_interaction_{}", i), &val)?;
        interaction_values.push(val);
    }

    // PLONK interaction columns 4-7 (2 samples each: original and shifted)
    for i in 4..8 {
        // Original sample (at oods_point)
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][0])?;
        ldm.write(format!("plonk_interaction_{}", i), &val)?;
        interaction_values.push(val.clone());

        // Shifted sample (at oods_point * g)
        let val_shifted = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][1])?;
        ldm.write(format!("plonk_interaction_{}_shifted", i), &val_shifted)?;
        interaction_values.push(val_shifted);
    }

    // Poseidon interaction columns 8-11 (1 sample each)
    for i in 8..12 {
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][0])?;
        ldm.write(format!("poseidon_interaction_{}", i - 8), &val)?;
        interaction_values.push(val);
    }

    // Poseidon interaction columns 12-15 (2 samples each)
    for i in 12..16 {
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][0])?;
        ldm.write(format!("poseidon_interaction_{}", i - 8), &val)?;
        interaction_values.push(val.clone());

        let val_shifted = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[2][i][1])?;
        ldm.write(format!("poseidon_interaction_{}_shifted", i - 8), &val_shifted)?;
        interaction_values.push(val_shifted);
    }

    // Mix all interaction values into channel
    channel_var.mix_felts(&interaction_values);

    // Tree[3] = Composition columns (4 total)
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
        composition_0,
        composition_1,
        composition_2,
        composition_3,
    ]);

    // Draw after_sampled_values_random_coeff
    let after_sampled_values_random_coeff = channel_var.draw_felt();
    ldm.write("after_sampled_values_random_coeff", &after_sampled_values_random_coeff)?;

    ldm.write("channel_var_after_sampled_values", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
