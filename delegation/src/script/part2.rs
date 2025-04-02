use crate::decommit::{DelegatedDecommitBar, DelegatedDecommitHints};
use crate::folding::{DelegatedFirstLayerBar, DelegatedFirstLayerHints};
use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
    proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    first_layer_hints: &DelegatedFirstLayerHints,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let queries_felt_1: QM31Bar = ldm.read("delegated_queries_felt_1")?;
    let queries_felt_2: QM31Bar = ldm.read("delegated_queries_felt_2")?;

    let mut queries = vec![];
    queries.extend(queries_felt_1.to_m31_array());
    queries.extend(queries_felt_2.to_m31_array());

    let interaction_commitment_var: Sha256HashBar = ldm.read("delegated_interaction_commit")?;
    let composition_commitment_var: Sha256HashBar = ldm.read("delegated_composition_commit")?;

    let decommit_interaction_hints = DelegatedDecommitHints::compute(&fiat_shamir_hints, &proof, 2);
    let decommit_interaction_var = DelegatedDecommitBar::new_hint(&cs, decommit_interaction_hints)?;
    decommit_interaction_var.verify(
        &queries,
        fiat_shamir_hints.max_first_layer_column_log_size as usize,
        &interaction_commitment_var,
    )?;
    let decommit_interaction_input_elements = decommit_interaction_var.input_elements()?;
    for (i, elem) in decommit_interaction_input_elements.iter().enumerate() {
        ldm.write(format!("delegated_decommit_interaction_input_{}", i), elem)?;
    }

    let decommit_composition_hints = DelegatedDecommitHints::compute(&fiat_shamir_hints, &proof, 3);
    let decommit_composition_var = DelegatedDecommitBar::new_hint(&cs, decommit_composition_hints)?;
    decommit_composition_var.verify(
        &queries,
        fiat_shamir_hints.max_first_layer_column_log_size as usize,
        &composition_commitment_var,
    )?;
    let decommit_composition_input_elements = decommit_composition_var.input_elements()?;
    for (i, elem) in decommit_composition_input_elements.iter().enumerate() {
        ldm.write(format!("delegated_decommit_composition_input_{}", i), elem)?;
    }

    let first_layer_var = DelegatedFirstLayerBar::new_hint(&cs, first_layer_hints.clone())?;

    let first_layer_commitment_var: Sha256HashBar = ldm.read("delegated_first_layer_commit")?;
    first_layer_var.verify(
        &queries,
        fiat_shamir_hints.max_first_layer_column_log_size as usize,
        &first_layer_commitment_var,
    )?;
    let first_layer_input_elements = first_layer_var.input_elements()?;
    for (i, elem) in first_layer_input_elements.iter().enumerate() {
        ldm.write(format!("delegated_first_layer_input_{}", i), elem)?;
    }

    ldm.save()?;
    Ok(cs)
}
