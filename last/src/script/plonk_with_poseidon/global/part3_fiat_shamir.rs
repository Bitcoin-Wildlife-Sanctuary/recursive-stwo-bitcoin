//! PlonkWithPoseidon Fiat-Shamir Script Part 3
//!
//! This script loads all 50 preprocessed columns and mixes them into the channel:
//! - 10 PLONK preprocessed columns
//! - 40 Poseidon preprocessed columns

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

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_oods_t")?;

    // Tree[0] = Preprocessed columns (50 total)
    // PLONK preprocessed: 10 columns (indices 0-9)
    // Poseidon preprocessed: 40 columns (indices 10-49)

    let mut preprocessed_values = Vec::with_capacity(50);

    // PLONK preprocessed columns (10)
    let plonk_prep_names = [
        "plonk_prep_a_wire",
        "plonk_prep_b_wire",
        "plonk_prep_c_wire",
        "plonk_prep_op",
        "plonk_prep_mult_a",
        "plonk_prep_mult_b",
        "plonk_prep_mult_c",
        "plonk_prep_poseidon_wire",
        "plonk_prep_mult_poseidon",
        "plonk_prep_enforce_c_m31",
    ];

    for (i, name) in plonk_prep_names.iter().enumerate() {
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][i][0])?;
        ldm.write(*name, &val)?;
        preprocessed_values.push(val);
    }

    // Poseidon preprocessed columns (40)
    // is_first_round, is_last_round, is_full_round, round_id
    let poseidon_prep_base_names = [
        "poseidon_prep_is_first_round",
        "poseidon_prep_is_last_round",
        "poseidon_prep_is_full_round",
        "poseidon_prep_round_id",
    ];

    for (i, name) in poseidon_prep_base_names.iter().enumerate() {
        let idx = 10 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][idx][0])?;
        ldm.write(*name, &val)?;
        preprocessed_values.push(val);
    }

    // rc0[0..15] - 16 columns
    for i in 0..16 {
        let idx = 14 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][idx][0])?;
        ldm.write(format!("poseidon_prep_rc0_{}", i), &val)?;
        preprocessed_values.push(val);
    }

    // rc1[0..15] - 16 columns
    for i in 0..16 {
        let idx = 30 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][idx][0])?;
        ldm.write(format!("poseidon_prep_rc1_{}", i), &val)?;
        preprocessed_values.push(val);
    }

    // external_idx_1, external_idx_2, is_external_idx_1_nonzero, is_external_idx_2_nonzero
    let poseidon_prep_suffix_names = [
        "poseidon_prep_external_idx_1",
        "poseidon_prep_external_idx_2",
        "poseidon_prep_is_external_idx_1_nonzero",
        "poseidon_prep_is_external_idx_2_nonzero",
    ];

    for (i, name) in poseidon_prep_suffix_names.iter().enumerate() {
        let idx = 46 + i;
        let val = QM31Bar::new_hint(&cs, proof.stark_proof.sampled_values[0][idx][0])?;
        ldm.write(*name, &val)?;
        preprocessed_values.push(val);
    }

    assert_eq!(preprocessed_values.len(), 50, "Expected 50 preprocessed columns");

    // Mix all preprocessed values into channel
    channel_var.mix_felts(&preprocessed_values);

    ldm.write("channel_var_after_preprocessed", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
