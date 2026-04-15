//! Decommitment hints for PlonkWithPoseidon Bitcoin script verification
//!
//! This module provides decommitment proof structures for verifying
//! Merkle tree commitments in PlonkWithPoseidon proofs.

use crate::script::plonk_with_poseidon::hints::PwpFiatShamirHints;
use anyhow::Result;
use itertools::Itertools;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use recursive_stwo_primitives::bits::split_be_bits;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::utils::hash_many_m31;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::vcs::prover::MerkleDecommitment;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

/// Single leaf Merkle proof structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PwpSingleLeafMerkleProof {
    pub query: usize,
    pub sibling_hashes: Vec<Sha256Hash>,
    pub columns: Vec<M31>,
    pub root: Sha256Hash,
    pub depth: usize,
}

impl PwpSingleLeafMerkleProof {
    pub fn from_stwo_proof(
        max_log_size: u32,
        raw_queries: &[usize],
        values: &[BaseField],
        root: Sha256Hash,
        n_columns_per_log_size: &BTreeMap<u32, usize>,
        merkle_decommitment: &MerkleDecommitment<Sha256MerkleHasher>,
    ) -> Vec<Self> {
        // Find out all the queried positions and sort them
        let mut queries = raw_queries.to_vec();
        queries.sort_unstable();
        queries.dedup();

        // Create the new value map
        let mut value_iterator = values.into_iter();

        let mut queries_values_map = HashMap::new();
        for &query in queries.iter() {
            let mut v = vec![];
            for _ in 0..*n_columns_per_log_size.get(&max_log_size).unwrap() {
                v.push(*value_iterator.next().unwrap());
            }
            queries_values_map.insert(query, v);
        }

        // Require the column witness to be empty (all values are provided)
        assert_eq!(merkle_decommitment.column_witness.len(), 0);

        // Turn hash witness into an iterator
        let mut hash_iterator = merkle_decommitment.hash_witness.iter();

        // Create the merkle partial tree
        let mut hash_layers: Vec<HashMap<usize, Sha256Hash>> = vec![];

        // Create the leaf layer
        let mut hash_layer = HashMap::new();
        for (&query, value) in queries_values_map.iter() {
            hash_layer.insert(query, Sha256MerkleHasher::hash_node(None, value));
        }
        hash_layers.push(hash_layer);

        let mut positions = queries.to_vec();
        positions.sort_unstable();

        // Create the intermediate layers
        for i in 0..max_log_size as usize {
            let mut layer = HashMap::new();
            let mut parents = BTreeSet::new();

            for &position in positions.iter() {
                if !layer.contains_key(&(position >> 1)) {
                    let sibling_idx = position ^ 1;

                    let hash = if let Some(sibling) = hash_layers[i].get(&sibling_idx) {
                        let (left, right) = if position & 1 == 0 {
                            (hash_layers[i].get(&position).unwrap(), sibling)
                        } else {
                            (sibling, hash_layers[i].get(&position).unwrap())
                        };
                        Sha256MerkleHasher::hash_node(Some((*left, *right)), &[])
                    } else {
                        let sibling = hash_iterator.next().unwrap();
                        hash_layers[i].insert(sibling_idx, *sibling);
                        let (left, right) = if position & 1 == 0 {
                            (hash_layers[i].get(&position).unwrap(), sibling)
                        } else {
                            (sibling, hash_layers[i].get(&position).unwrap())
                        };
                        Sha256MerkleHasher::hash_node(Some((*left, *right)), &[])
                    };

                    layer.insert(position >> 1, hash);
                    parents.insert(position >> 1);
                }
            }

            hash_layers.push(layer);
            positions = parents.iter().copied().collect::<Vec<usize>>();
        }

        assert_eq!(hash_iterator.next(), None);
        assert_eq!(value_iterator.next(), None);

        // Cherry-pick the Merkle tree paths to construct the deterministic proofs
        let mut res = vec![];
        for &query in raw_queries.iter() {
            let mut sibling_hashes = vec![];

            let mut cur = query;
            for layer in hash_layers.iter().take(max_log_size as usize) {
                sibling_hashes.push(*layer.get(&(cur ^ 1)).unwrap());
                cur >>= 1;
            }

            res.push(PwpSingleLeafMerkleProof {
                query,
                sibling_hashes,
                columns: queries_values_map.get(&query).unwrap().clone(),
                root: root.clone(),
                depth: max_log_size as usize,
            });
        }
        res
    }

    pub fn verify(&self) {
        let mut cur_hash = Sha256MerkleHasher::hash_node(None, &self.columns);
        for i in 0..self.depth {
            cur_hash = Sha256MerkleHasher::hash_node(
                if (self.query >> i) & 1 == 0 {
                    Some((cur_hash, self.sibling_hashes[i]))
                } else {
                    Some((self.sibling_hashes[i], cur_hash))
                },
                &[],
            );
        }
        assert_eq!(cur_hash, self.root);
    }
}

/// Bitcoin script variable for single path Merkle proof
#[derive(Clone)]
pub struct PwpSinglePathMerkleProofBar {
    pub cs: BitcoinSystemRef,
    pub value: PwpSingleLeafMerkleProof,
    pub sibling_hashes: Vec<Sha256HashBar>,
    pub columns: Vec<M31Bar>,
}

impl AllocBar for PwpSinglePathMerkleProofBar {
    type Value = PwpSingleLeafMerkleProof;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value.clone())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut sibling_hashes = vec![];
        for sibling_hash in data.sibling_hashes.iter() {
            sibling_hashes.push(Sha256HashBar::new_variable(cs, sibling_hash.clone(), mode)?);
        }

        let mut columns = vec![];
        for column in data.columns.iter() {
            columns.push(M31Bar::new_variable(cs, column.clone(), mode)?);
        }

        Ok(Self {
            cs: cs.clone(),
            value: data.clone(),
            sibling_hashes,
            columns,
        })
    }
}

impl PwpSinglePathMerkleProofBar {
    pub fn verify(&self, query: &M31Bar, log_size: usize, root: &Sha256HashBar) -> Result<()> {
        let mut bits_vars = split_be_bits(query, log_size)?;
        if log_size > self.sibling_hashes.len() {
            for i in 0..(log_size - self.sibling_hashes.len()) {
                bits_vars[i].drop();
            }
            bits_vars.drain(..(log_size - self.sibling_hashes.len()));
        }
        let mut columns = self.columns.clone();
        columns.reverse();
        let cur_hash = hash_many_m31(&self.cs, &columns)?;

        let mut input_idxs = vec![root.variable];
        for (bit_var, hash_var) in bits_vars
            .iter()
            .rev()
            .zip_eq(self.sibling_hashes.iter().rev())
        {
            input_idxs.push(hash_var.variable);
            input_idxs.push(bit_var.variable);
        }
        input_idxs.push(cur_hash.variable);

        let cs = query.cs().and(&root.cs());
        cs.insert_script_complex(
            verify_merkle_proof,
            input_idxs,
            &Options::new().with_u32("log_size", self.sibling_hashes.len() as u32),
        )
    }
}

fn verify_merkle_proof(_: &mut Stack, options: &Options) -> Result<Script> {
    let log_size = options.get_u32("log_size")?;
    Ok(script! {
        for _ in 0..log_size {
            OP_SWAP
            OP_NOTIF OP_SWAP OP_ENDIF
            OP_CAT OP_SHA256
        }
        OP_EQUALVERIFY
    })
}

/// Decommitment hints for a specific tree in PlonkWithPoseidon proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwpDecommitHints {
    pub proofs: Vec<PwpSingleLeafMerkleProof>,
}

impl PwpDecommitHints {
    pub fn compute(
        fiat_shamir_hints: &PwpFiatShamirHints<Sha256MerkleChannel>,
        proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
        round: usize,
    ) -> Self {
        let max_log_size = *fiat_shamir_hints.n_columns_per_log_size[round]
            .keys()
            .max()
            .unwrap();

        let proofs = PwpSingleLeafMerkleProof::from_stwo_proof(
            max_log_size,
            &fiat_shamir_hints
                .unsorted_query_positions_per_log_size
                .get(&max_log_size)
                .unwrap(),
            &proof.stark_proof.queried_values[round],
            proof.stark_proof.commitments[round],
            &fiat_shamir_hints.n_columns_per_log_size[round],
            &proof.stark_proof.decommitments[round],
        );

        for proof in proofs.iter() {
            proof.verify();
        }

        PwpDecommitHints { proofs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;

    #[test]
    fn test_pwp_decommit_hints() {
        let proof_bytes = std::fs::read("../data/poseidon_accelerated_proof.bin")
            .expect("Failed to load proof");
        let proof: PlonkWithPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(&proof_bytes).unwrap();

        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };
        let inputs: Vec<(usize, stwo_prover::core::fields::qm31::QM31)> = vec![];

        let fiat_shamir_hints =
            PwpFiatShamirHints::<Sha256MerkleChannel>::new(&proof, config, &inputs);

        // Test decommitment for each tree
        for round in 0..4 {
            let decommit_hints = PwpDecommitHints::compute(&fiat_shamir_hints, &proof, round);
            println!(
                "Round {}: {} proofs, {} columns per proof",
                round,
                decommit_hints.proofs.len(),
                if !decommit_hints.proofs.is_empty() {
                    decommit_hints.proofs[0].columns.len()
                } else {
                    0
                }
            );
        }

        println!("PwpDecommitHints test passed!");
    }
}
