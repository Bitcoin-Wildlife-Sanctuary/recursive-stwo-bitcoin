use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

pub fn generate_cs(
    fiat_shamir_hints: &FiatShamirHints<Sha256MerkleChannel>,
    proof: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    config: PcsConfig,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    todo!()
}
