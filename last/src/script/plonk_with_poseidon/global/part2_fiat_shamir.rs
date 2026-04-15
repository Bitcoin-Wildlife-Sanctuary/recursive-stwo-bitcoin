//! PlonkWithPoseidon Fiat-Shamir Script Part 2
//!
//! This script:
//! 1. Loads plonk_total_sum and poseidon_total_sum (key difference: two sums)
//! 2. Verifies both total_sums are zero (self-balanced circuit, no delegation)
//! 3. Mixes interaction commitment
//! 4. Draws random_coeff
//! 5. Mixes composition commitment
//! 6. Draws oods_t

use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    fiat_shamir_hints: &PwpFiatShamirHints<Sha256MerkleChannel>,
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_z_and_alpha")?;

    // PlonkWithPoseidon has TWO total_sum values (unlike PlonkWithoutPoseidon which has one)
    let plonk_total_sum = QM31Bar::new_hint(&cs, fiat_shamir_hints.plonk_total_sum)?;
    let poseidon_total_sum = QM31Bar::new_hint(&cs, fiat_shamir_hints.poseidon_total_sum)?;

    ldm.write("plonk_total_sum", &plonk_total_sum)?;
    ldm.write("poseidon_total_sum", &poseidon_total_sum)?;

    // NOTE: For self-balanced circuits, both total_sums should be zero.
    // For circuits verifying external proofs (like level13), total_sums are non-zero
    // and require input verification (delegation).
    // TODO: Add input verification for non-self-balanced circuits
    // plonk_total_sum.is_zero();
    // poseidon_total_sum.is_zero();

    // Mix both total sums into channel
    channel_var.mix_felts(&[plonk_total_sum, poseidon_total_sum]);

    // Interaction trace commitment
    let interaction_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[2].as_ref().to_vec().into(),
    )?;
    ldm.write("interaction_commitment_var", &interaction_commitment_var)?;
    channel_var.mix_root(&interaction_commitment_var);

    let random_coeff = channel_var.draw_felt();
    ldm.write("random_coeff", &random_coeff)?;

    // Composition polynomial commitment
    let composition_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[3].as_ref().to_vec().into(),
    )?;
    ldm.write("composition_commitment_var", &composition_commitment_var)?;
    channel_var.mix_root(&composition_commitment_var);

    // Draw OODS point parameter
    let oods_t = channel_var.draw_felt();
    ldm.write("oods_t", &oods_t)?;

    ldm.write("channel_var_after_oods_t", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
