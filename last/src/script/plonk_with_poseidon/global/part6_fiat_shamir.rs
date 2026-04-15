//! PlonkWithPoseidon Fiat-Shamir Script Part 6
//!
//! This script handles:
//! 1. FRI first layer commitment and alpha
//! 2. FRI inner layer commitments and alphas (10 layers for log_size=15)
//! 3. Last layer polynomial
//! 4. PoW verification
//! 5. Query generation

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::bits::split_hi_lo;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::pow::verify_pow;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    config: PcsConfig,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var: Sha256ChannelBar = ldm.read("channel_var_after_sampled_values")?;

    // FRI first layer commitment
    let first_layer_commitment =
        Sha256HashBar::new_hint(&cs, proof.stark_proof.fri_proof.first_layer.commitment)?;
    channel_var.mix_root(&first_layer_commitment);
    ldm.write("first_layer_commitment", &first_layer_commitment)?;

    let first_layer_alpha = channel_var.draw_felt();
    ldm.write("first_layer_alpha", &first_layer_alpha)?;

    // FRI inner layers: 10 for PlonkWithPoseidon (log_size=15 -> 22 - 7 blowup - 5 last_layer = 10)
    // This may vary based on config, but typically fewer than PlonkWithoutPoseidon's 18
    let n_inner_layers = proof.stark_proof.fri_proof.inner_layers.len();

    for i in 0..n_inner_layers {
        let inner_layer_commitment =
            Sha256HashBar::new_hint(&cs, proof.stark_proof.fri_proof.inner_layers[i].commitment)?;
        channel_var.mix_root(&inner_layer_commitment);
        ldm.write(format!("inner_layer_commitment_{}", i), &inner_layer_commitment)?;

        let inner_layer_alpha = channel_var.draw_felt();
        ldm.write(format!("inner_layer_alpha_{}", i), &inner_layer_alpha)?;
    }

    // Last layer polynomial
    // For PlonkWithPoseidon with log_blowup=7, last_layer has log_size=7 (128 coefficients)
    let n_last_layer_coeffs = proof.stark_proof.fri_proof.last_layer_poly.coeffs.len();

    // Mix all last layer coefficients at once (more efficient)
    let mut last_layer_coeffs = Vec::with_capacity(n_last_layer_coeffs);
    for i in 0..n_last_layer_coeffs {
        let coeff = QM31Bar::new_hint(&cs, proof.stark_proof.fri_proof.last_layer_poly.coeffs[i])?;
        ldm.write(format!("last_layer_coeff_{}", i), &coeff)?;
        last_layer_coeffs.push(coeff);
    }
    channel_var.mix_felts(&last_layer_coeffs);

    // Mix nonce for PoW
    let nonce = &StrBar::new_hint(&cs, proof.stark_proof.proof_of_work.to_le_bytes().to_vec())?
        + &StrBar::new_constant(&cs, [0x0; 24].to_vec())?;
    channel_var.mix_str(&nonce);

    // Verify PoW
    verify_pow(&channel_var, config.pow_bits as usize)?;

    // Generate query positions
    assert_eq!(config.fri_config.n_queries, 8);
    let [raw_queries_felt_1, raw_queries_felt_2] = channel_var.draw_felts();

    let mut raw_queries = raw_queries_felt_1.to_m31_array().to_vec();
    raw_queries.extend(raw_queries_felt_2.to_m31_array());

    // For PlonkWithPoseidon:
    // - Preprocessed/trace/interaction columns: log_size 24 (15 + 9 for first FRI layer with log_blowup=7)
    // - Composition columns: log_size 27 (20 + 7)
    // max_first_layer_column_log_size = 27 (from composition columns)
    let max_log_size = 27;

    let mut queries = vec![];
    for raw_query in raw_queries.iter() {
        let (hi, lo) = split_hi_lo(raw_query, max_log_size)?;
        hi.drop();
        queries.push(lo);
    }

    for i in 0..8 {
        ldm.write(format!("query_{}", i), &queries[i])?;
    }

    ldm.write("channel_var_final", &channel_var)?;

    ldm.save()?;
    Ok(cs)
}
