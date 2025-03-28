use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use itertools::Itertools;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::{bitcoin_num_to_bytes, Sha256HashBar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::utils::hash_many_m31;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;
use stwo_prover::core::vcs::prover::MerkleDecommitment;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SingleLeafMerkleProof {
    pub query: usize,

    pub sibling_hashes: Vec<Sha256Hash>,
    pub columns: Vec<M31>,

    pub root: Sha256Hash,
    pub depth: usize,
}

impl SingleLeafMerkleProof {
    pub fn from_stwo_proof(
        max_log_size: u32,
        raw_queries: &[usize],
        values: &[BaseField],
        root: Sha256Hash,
        n_columns_per_log_size: &BTreeMap<u32, usize>,
        merkle_decommitment: &MerkleDecommitment<Sha256Poseidon31MerkleHasher>,
    ) -> Vec<Self> {
        // find out all the queried positions and sort them
        let mut queries = raw_queries.to_vec();
        queries.sort_unstable();
        queries.dedup();

        // create the new value map
        let mut value_iterator = values.into_iter();

        let mut queries_values_map = HashMap::new();
        for &query in queries.iter() {
            let mut v = vec![];
            for _ in 0..*n_columns_per_log_size.get(&max_log_size).unwrap() {
                v.push(*value_iterator.next().unwrap());
            }
            queries_values_map.insert(query, v);
        }

        // require the column witness to be empty
        // (all the values are provided)
        assert_eq!(merkle_decommitment.column_witness.len(), 0);

        // turn hash witness into an iterator
        let mut hash_iterator = merkle_decommitment.hash_witness.iter();

        // create the merkle partial tree
        let mut hash_layers: Vec<HashMap<usize, Sha256Hash>> = vec![];

        // create the leaf layer
        let mut hash_layer = HashMap::new();
        for (&query, value) in queries_values_map.iter() {
            hash_layer.insert(query, Sha256Poseidon31MerkleHasher::hash_node(None, value));
        }
        hash_layers.push(hash_layer);

        let mut positions = queries.to_vec();
        positions.sort_unstable();

        // create the intermediate layers
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
                        Sha256Poseidon31MerkleHasher::hash_node(Some((*left, *right)), &[])
                    } else {
                        let sibling = hash_iterator.next().unwrap();
                        hash_layers[i].insert(sibling_idx, *sibling);
                        let (left, right) = if position & 1 == 0 {
                            (hash_layers[i].get(&position).unwrap(), sibling)
                        } else {
                            (sibling, hash_layers[i].get(&position).unwrap())
                        };
                        Sha256Poseidon31MerkleHasher::hash_node(Some((*left, *right)), &[])
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

        // cheery-pick the Merkle tree paths to construct the deterministic proofs
        let mut res = vec![];
        for &query in raw_queries.iter() {
            let mut sibling_hashes = vec![];

            let mut cur = query;
            for layer in hash_layers.iter().take(max_log_size as usize) {
                sibling_hashes.push(*layer.get(&(cur ^ 1)).unwrap());
                cur >>= 1;
            }

            res.push(SingleLeafMerkleProof {
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
        let mut cur_hash = Sha256Poseidon31MerkleHasher::hash_node(None, &self.columns);

        for i in 0..self.depth {
            cur_hash = Sha256Poseidon31MerkleHasher::hash_node(
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

#[derive(Debug, Clone)]
pub struct DelegatedDecommitHints {
    pub precomputed_proofs: Vec<SingleLeafMerkleProof>,
    pub trace_proofs: Vec<SingleLeafMerkleProof>,
    pub interaction_proofs: Vec<SingleLeafMerkleProof>,
    pub composition_proofs: Vec<SingleLeafMerkleProof>,
}

#[derive(Clone)]
pub struct SingleLeafMerkleProofBar {
    pub cs: BitcoinSystemRef,
    pub value: SingleLeafMerkleProof,

    pub query: M31Bar,
    pub sibling_hashes: Vec<Sha256HashBar>,
    pub columns: Vec<M31Bar>,
}

impl AllocBar for SingleLeafMerkleProofBar {
    type Value = SingleLeafMerkleProof;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value.clone())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let query = M31Bar::new_variable(cs, M31::from(data.query as u32), mode)?;

        let mut sibling_hashes = vec![];
        for sibling_hash in data.sibling_hashes.iter() {
            sibling_hashes.push(Sha256HashBar::new_variable(cs, sibling_hash.clone(), mode)?);
        }

        let columns = if data.columns.len() <= 8 {
            let mut columns = vec![];
            for column in data.columns.iter() {
                columns.push(M31Bar::new_variable(cs, column.clone(), mode)?);
            }
            columns
        } else {
            let mut columns = vec![];
            let data = Poseidon31MerkleHasher::hash_column_get_rate(&data.columns);
            for column in data.0 {
                columns.push(M31Bar::new_variable(cs, column, mode)?);
            }
            columns
        };

        Ok(Self {
            cs: cs.clone(),
            value: data.clone(),
            query,
            sibling_hashes,
            columns,
        })
    }
}

impl SingleLeafMerkleProofBar {
    pub fn verify(&self, root: &Sha256HashBar) -> Result<()> {
        let mut column_hash = hash_many_m31(&self.cs, &self.columns)?;

        todo!()
    }
}

impl DelegatedDecommitHints {
    pub fn compute(
        fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
        proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    ) -> Self {
        let mut precomputed_proofs = vec![];
        let mut trace_proofs = vec![];
        let mut interaction_proofs = vec![];
        let mut composition_proofs = vec![];

        for (i, v) in [
            &mut precomputed_proofs,
            &mut trace_proofs,
            &mut interaction_proofs,
            &mut composition_proofs,
        ]
        .iter_mut()
        .enumerate()
        {
            let max_log_size = *fiat_shamir_hints.n_columns_per_log_size[i]
                .keys()
                .max()
                .unwrap();

            **v = SingleLeafMerkleProof::from_stwo_proof(
                max_log_size,
                &fiat_shamir_hints
                    .unsorted_query_positions_per_log_size
                    .get(&max_log_size)
                    .unwrap(),
                &proof.stark_proof.queried_values[i],
                proof.stark_proof.commitments[i],
                &fiat_shamir_hints.n_columns_per_log_size[i],
                &proof.stark_proof.decommitments[i],
            );

            for proof in v.iter() {
                proof.verify();
            }
        }

        DelegatedDecommitHints {
            precomputed_proofs,
            trace_proofs,
            interaction_proofs,
            composition_proofs,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::decommit::DelegatedDecommitHints;
    use circle_plonk_dsl_hints::FiatShamirHints;
    use num_traits::One;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
        Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
    };
    use stwo_prover::examples::plonk_with_poseidon::air::{
        verify_plonk_with_poseidon, PlonkWithPoseidonProof,
    };

    #[test]
    fn test_decommitment() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../data/hybrid_hash.bin")).unwrap();
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        verify_plonk_with_poseidon::<Sha256Poseidon31MerkleChannel>(
            proof.clone(),
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        )
        .unwrap();

        let fiat_shamir_hints = FiatShamirHints::<Sha256Poseidon31MerkleChannel>::new(
            &proof,
            config,
            &[
                (1, QM31::one()),
                (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
                (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
            ],
        );

        let _ = DelegatedDecommitHints::compute(&fiat_shamir_hints, &proof);
    }
}
