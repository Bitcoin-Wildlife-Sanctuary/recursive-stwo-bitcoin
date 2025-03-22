use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use itertools::Itertools;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::qm31::QM31Bar;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
    proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var = Sha256ChannelBar::default(&cs)?;

    // Preprocessed trace.
    let preprocessed_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[0].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&preprocessed_commitment_var);

    // Update the channel with the log sizes
    let mut d = [0u8; 32];
    d[0..4].copy_from_slice(&proof.stmt0.log_size_plonk.to_le_bytes());
    channel_var.mix_str(&StrBar::new_constant(&cs, d.to_vec())?);
    let mut d = [0u8; 32];
    d[0..4].copy_from_slice(&proof.stmt0.log_size_poseidon.to_le_bytes());
    channel_var.mix_str(&StrBar::new_constant(&cs, d.to_vec())?);

    // Trace.
    let trace_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[1].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&trace_commitment_var);

    // Draw interaction elements (specifically, z and alpha)
    let [z, alpha] = channel_var.draw_felts();

    // Update the channel with checksum
    let plonk_total_sum = QM31Bar::new_hint(&cs, fiat_shamir_hints.plonk_total_sum)?;
    let poseidon_total_sum = QM31Bar::new_hint(&cs, fiat_shamir_hints.poseidon_total_sum)?;
    channel_var.mix_felts(&[plonk_total_sum, poseidon_total_sum]);

    // Interaction trace.
    let interaction_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[2].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&interaction_commitment_var);

    let random_coeff = channel_var.draw_felt();

    // Read composition polynomial commitment.
    let composition_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[3].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&composition_commitment_var);

    // Draw OODS point.
    let oods_t = channel_var.draw_felt();

    // Calculate the hash of the column values
    let sampled_values_hash = Poseidon31MerkleHasher::hash_column_get_rate(
        &proof
            .stark_proof
            .sampled_values
            .clone()
            .flatten_cols()
            .iter()
            .flat_map(|v| v.to_m31_array())
            .collect_vec(),
    );

    let sampled_values_hash = [
        QM31Bar::new_hint(
            &cs,
            QM31::from_m31(
                sampled_values_hash.0[0],
                sampled_values_hash.0[1],
                sampled_values_hash.0[2],
                sampled_values_hash.0[3],
            ),
        )?,
        QM31Bar::new_hint(
            &cs,
            QM31::from_m31(
                sampled_values_hash.0[4],
                sampled_values_hash.0[5],
                sampled_values_hash.0[6],
                sampled_values_hash.0[7],
            ),
        )?,
    ];

    channel_var.mix_felts(&sampled_values_hash);

    let after_sampled_values_random_coeff = channel_var.draw_felt();

    let first_layer_commit_var =
        Sha256HashBar::new_hint(&cs, proof.stark_proof.fri_proof.first_layer.commitment)?;
    channel_var.mix_root(&first_layer_commit_var);

    let first_layer_folding_alpha = channel_var.draw_felt();

    let mut inner_layers_commit_vars = vec![];
    let mut inner_layers_folding_alphas = vec![];

    for inner_layer in proof.stark_proof.fri_proof.inner_layers.iter() {
        let commit_var = Sha256HashBar::new_hint(&cs, inner_layer.commitment)?;
        channel_var.mix_root(&commit_var);
        inner_layers_commit_vars.push(commit_var);

        inner_layers_folding_alphas.push(channel_var.draw_felt());
    }

    let coeffs = &proof.stark_proof.fri_proof.last_layer_poly.coeffs;
    assert!(coeffs.len() > 2);

    let coeffs_hash = Poseidon31MerkleHasher::hash_column_get_rate(
        &coeffs.iter().flat_map(|v| v.to_m31_array()).collect_vec(),
    );
    let coeffs_hash = [
        QM31Bar::new_hint(
            &cs,
            QM31::from_m31(
                coeffs_hash.0[0],
                coeffs_hash.0[1],
                coeffs_hash.0[2],
                coeffs_hash.0[3],
            ),
        )?,
        QM31Bar::new_hint(
            &cs,
            QM31::from_m31(
                coeffs_hash.0[4],
                coeffs_hash.0[5],
                coeffs_hash.0[6],
                coeffs_hash.0[7],
            ),
        )?,
    ];

    channel_var.mix_felts(&coeffs_hash);

    ldm.save()?;
    Ok(cs)
}
