use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use itertools::Itertools;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use recursive_stwo_primitives::bits::split_be_bits;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::utils::hash_many_m31;
use serde::{Deserialize, Serialize};
use std::cmp::max;
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
pub struct DelegatedSingleLeafMerkleProof {
    pub query: usize,

    pub sibling_hashes: Vec<Sha256Hash>,
    pub columns: Vec<M31>,

    pub root: Sha256Hash,
    pub depth: usize,
}

impl DelegatedSingleLeafMerkleProof {
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

            res.push(DelegatedSingleLeafMerkleProof {
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

#[derive(Clone)]
pub struct DelegatingSinglePathMerkleProofBar {
    pub cs: BitcoinSystemRef,
    pub value: DelegatedSingleLeafMerkleProof,

    pub sibling_hashes: Vec<Sha256HashBar>,
    pub columns: Vec<M31Bar>,
}

impl AllocBar for DelegatingSinglePathMerkleProofBar {
    type Value = DelegatedSingleLeafMerkleProof;

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
            sibling_hashes,
            columns,
        })
    }
}

impl DelegatingSinglePathMerkleProofBar {
    pub fn verify(&self, query: &M31Bar, log_size: usize, root: &Sha256HashBar) -> Result<()> {
        let mut bits_vars = split_be_bits(query, log_size)?;
        if log_size > self.sibling_hashes.len() {
            for i in 0..(log_size - self.sibling_hashes.len()) {
                bits_vars[i].drop();
            }
            bits_vars.drain(..(log_size - self.sibling_hashes.len()));
        }
        let cur_hash = hash_many_m31(&self.cs, &self.columns)?;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedDecommitHints {
    pub proofs: Vec<DelegatedSingleLeafMerkleProof>,
}

impl DelegatedDecommitHints {
    pub fn compute(
        fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
        proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
        round: usize,
    ) -> Self {
        let max_log_size = *fiat_shamir_hints.n_columns_per_log_size[round]
            .keys()
            .max()
            .unwrap();

        let proofs = DelegatedSingleLeafMerkleProof::from_stwo_proof(
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

        DelegatedDecommitHints { proofs }
    }
}

#[derive(Clone)]
pub struct DelegatedDecommitBar {
    pub cs: BitcoinSystemRef,
    pub proofs: Vec<DelegatingSinglePathMerkleProofBar>,
}

impl AllocBar for DelegatedDecommitBar {
    type Value = DelegatedDecommitHints;

    fn value(&self) -> Result<Self::Value> {
        Ok(DelegatedDecommitHints {
            proofs: self.proofs.iter().map(|v| v.value.clone()).collect_vec(),
        })
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        value: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut proofs = vec![];
        for proof in value.proofs.iter() {
            proofs.push(DelegatingSinglePathMerkleProofBar::new_variable(
                cs,
                proof.clone(),
                mode,
            )?);
        }

        Ok(Self {
            cs: cs.clone(),
            proofs,
        })
    }
}

impl DelegatedDecommitBar {
    pub fn verify(
        &self,
        queries: &[M31Bar],
        log_size: usize,
        commitment_var: &Sha256HashBar,
    ) -> Result<()> {
        for (proof, query) in self.proofs.iter().zip_eq(queries.iter()) {
            proof.verify(query, log_size, commitment_var)?;
        }
        Ok(())
    }

    pub fn input_elements(&self) -> Result<Vec<QM31Bar>> {
        let mut results = vec![];
        let zero = M31Bar::new_constant(&self.cs, M31::zero())?;

        let f = |results: &mut Vec<QM31Bar>, columns: &[M31Bar]| {
            assert!(columns.len() <= 8);

            let mut first = Vec::with_capacity(4);
            for i in 0..max(4, columns.len()) {
                first.push(columns[i].clone());
            }
            first.resize(4, zero.clone());

            results.push(QM31Bar::from_m31(
                &first[0], &first[1], &first[2], &first[3],
            ));

            if columns.len() > 4 {
                let mut second = Vec::with_capacity(4);
                for i in 4..columns.len() {
                    second.push(columns[i].clone());
                }
                second.resize(4, zero.clone());

                results.push(QM31Bar::from_m31(
                    &second[0], &second[1], &second[2], &second[3],
                ));
            }
        };

        for proof in self.proofs.iter() {
            f(&mut results, &proof.columns);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod test {
    use crate::decommit::{DelegatedDecommitBar, DelegatedDecommitHints};
    use circle_plonk_dsl_hints::FiatShamirHints;
    use num_traits::One;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_primitives::fields::m31::M31Bar;
    use stwo_prover::core::fields::m31::M31;
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
            bincode::deserialize(include_bytes!("../../../data/hybrid_hash.bin")).unwrap();
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

        let decommit_preprocessed_hints =
            DelegatedDecommitHints::compute(&fiat_shamir_hints, &proof, 0);

        let cs = BitcoinSystemRef::new_ref();
        let decommit_preprocessed_var =
            DelegatedDecommitBar::new_hint(&cs, decommit_preprocessed_hints).unwrap();

        let mut queries_vars = vec![];
        for query in fiat_shamir_hints.unsorted_query_positions_per_log_size
            [&fiat_shamir_hints.max_first_layer_column_log_size]
            .iter()
        {
            queries_vars.push(M31Bar::new_hint(&cs, M31::from(*query)).unwrap());
        }

        let preprocessed_commitment_var =
            Sha256HashBar::new_hint(&cs, fiat_shamir_hints.preprocessed_commitment).unwrap();

        decommit_preprocessed_var
            .verify(
                &queries_vars,
                fiat_shamir_hints.max_first_layer_column_log_size as usize,
                &preprocessed_commitment_var,
            )
            .unwrap();

        let _ = decommit_preprocessed_var.input_elements().unwrap();
        test_program(cs, script! {}).unwrap();
    }
}
