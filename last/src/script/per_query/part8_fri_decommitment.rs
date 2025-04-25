use crate::script::hints::folding::{
    LastFirstLayerHints, LastInnerLayersHints, LastSinglePairMerkleProofBar,
};
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;

pub fn generate_cs(
    query_idx: usize,
    last_first_layer_hints: &LastFirstLayerHints,
    last_inner_layers_hints: &LastInnerLayersHints,
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let query_28: M31Bar = ldm.read(format!("query_{}", query_idx))?;
    let first_layer_decommitment = LastSinglePairMerkleProofBar::new_hint(
        &cs,
        last_first_layer_hints.merkle_proofs[query_idx].clone(),
    )?;
    let first_layer_commitment: Sha256HashBar = ldm.read("first_layer_commitment")?;
    first_layer_decommitment.verify(&query_28, 28, &first_layer_commitment)?;

    ldm_per_query.write(
        "first_layer_self_28",
        &first_layer_decommitment.self_columns[&28],
    )?;
    ldm_per_query.write(
        "first_layer_self_26",
        &first_layer_decommitment.self_columns[&26],
    )?;
    ldm_per_query.write(
        "first_layer_sibling_28",
        &first_layer_decommitment.siblings_columns[&28],
    )?;
    ldm_per_query.write(
        "first_layer_sibling_26",
        &first_layer_decommitment.siblings_columns[&26],
    )?;

    for i in 0..18 {
        let inner_layer_decommitment = LastSinglePairMerkleProofBar::new_hint(
            &cs,
            last_inner_layers_hints.merkle_proofs[&(27 - i)][query_idx].clone(),
        )?;
        let inner_layer_commitment: Sha256HashBar =
            ldm.read(format!("inner_layer_commitment_{}", i))?;
        inner_layer_decommitment.verify(&query_28, 28, &inner_layer_commitment)?;
        ldm_per_query.write(
            format!("inner_layer_self_{}", i),
            &inner_layer_decommitment.self_columns[&((27 - i) as usize)],
        )?;
        ldm_per_query.write(
            format!("inner_layer_sibling_{}", i),
            &inner_layer_decommitment.siblings_columns[&((27 - i) as usize)],
        )?;
    }

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
