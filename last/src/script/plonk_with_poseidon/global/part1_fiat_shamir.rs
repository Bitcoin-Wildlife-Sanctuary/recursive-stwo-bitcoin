//! PlonkWithPoseidon Fiat-Shamir Script Part 1
//!
//! This script:
//! 1. Mixes preprocessed commitment into channel
//! 2. Mixes log_size_plonk AND log_size_poseidon (key difference from PlonkWithoutPoseidon)
//! 3. Mixes trace commitment into channel
//! 4. Draws interaction elements z and alpha

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var = Sha256ChannelBar::default(&cs)?;

    // Preprocessed trace commitment
    let preprocessed_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[0].as_ref().to_vec().into(),
    )?;
    ldm.write("preprocessed_commitment_var", &preprocessed_commitment_var)?;
    channel_var.mix_root(&preprocessed_commitment_var);

    // Update the channel with BOTH log sizes (key difference from PlonkWithoutPoseidon)
    // PlonkWithPoseidon has separate sizes for PLONK and Poseidon sub-circuits
    let mut d = [0u8; 32];
    d[0..4].copy_from_slice(&proof.stmt0.log_size_plonk.to_le_bytes());
    d[4..8].copy_from_slice(&proof.stmt0.log_size_poseidon.to_le_bytes());
    channel_var.mix_str(&StrBar::new_constant(&cs, d.to_vec())?);

    // Trace commitment
    let trace_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[1].as_ref().to_vec().into(),
    )?;
    ldm.write("trace_commitment_var", &trace_commitment_var)?;
    channel_var.mix_root(&trace_commitment_var);

    // Draw interaction elements (z and alpha)
    let [z, alpha] = channel_var.draw_felts();
    ldm.write("z", &z)?;
    ldm.write("alpha", &alpha)?;

    ldm.write("channel_var_after_z_and_alpha", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
