use crate::folding::{DelegatedInnerLayersHints, DelegatedInnerLayersPerLayerBar};
use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleChannel;

pub fn generate_cs(
    fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
    inner_layers_hints: &DelegatedInnerLayersHints,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let queries_felt_1: QM31Bar = ldm.read("delegated_queries_felt_1")?;
    let queries_felt_2: QM31Bar = ldm.read("delegated_queries_felt_2")?;

    let mut queries = vec![];
    queries.extend(queries_felt_1.to_m31_array());
    queries.extend(queries_felt_2.to_m31_array());

    for (i, (_, v)) in inner_layers_hints.merkle_proofs.iter().enumerate().take(4) {
        let inner_layer_var = DelegatedInnerLayersPerLayerBar::new_hint(&cs, v.to_vec())?;
        let inner_layer_commitment_var: Sha256HashBar = ldm.read(format!(
            "delegated_inner_layers_commit_{}",
            fiat_shamir_hints.inner_layer_commitments.len() - 1 - i
        ))?;
        inner_layer_var.verify(
            &queries,
            fiat_shamir_hints.max_first_layer_column_log_size as usize,
            &inner_layer_commitment_var,
        )?;
        let decommit_interaction_input_elements = inner_layer_var.input_elements()?;
        for (j, elem) in decommit_interaction_input_elements.iter().enumerate() {
            ldm.write(format!("delegated_inner_layers_input_{}_{}", i, j), elem)?;
        }
    }

    ldm.save()?;
    Ok(cs)
}
