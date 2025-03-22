use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;

pub fn generate_cs(
    fiat_shamir_hints: &FiatShamirHints<Sha256MerkleChannel>,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();

    let mut channel_var = Sha256ChannelBar::default(&cs)?;

    // Preprocessed trace.
    let trace_commitment_var = Sha256HashBar::new_hint(
        &cs,
        fiat_shamir_hints.trace_commitment.as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&trace_commitment_var);

    todo!()
}
