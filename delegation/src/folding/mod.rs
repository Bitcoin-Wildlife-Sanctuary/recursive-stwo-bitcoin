use anyhow::Result;
use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
use itertools::{zip_eq, Itertools};
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::basic::bool::BoolBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::treepp::*;
use recursive_stwo_primitives::bits::split_be_bits;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::utils::hash_many_m31;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_prover::core::fri::SparseEvaluation;
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::core::vcs::bitcoin_num_to_bytes;
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::vcs::prover::MerkleDecommitment;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::core::vcs::verifier::MerkleVerifier;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegatedSinglePairMerkleProof {
    pub query: usize,

    pub sibling_hashes: Vec<Sha256Hash>,

    pub self_columns: BTreeMap<usize, QM31>,
    pub siblings_columns: BTreeMap<usize, QM31>,

    pub root: Sha256Hash,
    pub depth: usize,
}

impl DelegatedSinglePairMerkleProof {
    pub fn verify(&self) {
        let mut self_hash = Sha256Poseidon31MerkleHasher::hash_node(
            None,
            &self
                .self_columns
                .get(&self.depth)
                .map_or(vec![], |v| v.to_m31_array().to_vec()),
        );
        let mut sibling_hash = Sha256Poseidon31MerkleHasher::hash_node(
            None,
            &self
                .siblings_columns
                .get(&self.depth)
                .map_or(vec![], |v| v.to_m31_array().to_vec()),
        );

        for i in 0..self.depth {
            let h = self.depth - i - 1;

            if !self.self_columns.contains_key(&h) {
                self_hash = Sha256Poseidon31MerkleHasher::hash_node(
                    if (self.query >> i) & 1 == 0 {
                        Some((self_hash, sibling_hash))
                    } else {
                        Some((sibling_hash, self_hash))
                    },
                    &vec![],
                );
                if i != self.depth - 1 {
                    sibling_hash = self.sibling_hashes[i];
                }
            } else {
                self_hash = Sha256Poseidon31MerkleHasher::hash_node(
                    if (self.query >> i) & 1 == 0 {
                        Some((self_hash, sibling_hash))
                    } else {
                        Some((sibling_hash, self_hash))
                    },
                    &self
                        .self_columns
                        .get(&h)
                        .map_or(vec![], |v| v.to_m31_array().to_vec()),
                );
                sibling_hash = {
                    let column_values = self
                        .siblings_columns
                        .get(&h)
                        .map_or(vec![], |v| v.to_m31_array().to_vec());

                    let mut hash = [0u8; 32];

                    let mut sha256 = Sha256::new();
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(column_values[0]));
                    Digest::update(&mut sha256, self.sibling_hashes[i]);
                    hash.copy_from_slice(sha256.finalize().as_slice());

                    for i in 1..column_values.len() {
                        let mut sha256 = sha2::Sha256::new();
                        Digest::update(&mut sha256, bitcoin_num_to_bytes(column_values[i]));
                        Digest::update(&mut sha256, &hash);
                        hash.copy_from_slice(sha256.finalize().as_slice());
                    }
                    Sha256Hash::from(hash.as_slice())
                };
            }
        }
        assert_eq!(self_hash, self.root);
    }

    pub fn from_stwo_proof(
        log_sizes_with_data: &BTreeSet<u32>,
        root: Sha256Hash,
        leaf_queries: &[usize],
        values: &[M31],
        decommitment: &MerkleDecommitment<Sha256Poseidon31MerkleHasher>,
    ) -> Vec<DelegatedSinglePairMerkleProof> {
        // require the column witness to be empty
        // (all the values are provided)
        assert_eq!(decommitment.column_witness.len(), 0);

        // get the max log_size
        let max_log_size = *log_sizes_with_data.iter().max().unwrap();

        let mut queries = leaf_queries.to_vec();

        // values iter
        let mut values_iter = values.iter();
        let mut hash_iter = decommitment.hash_witness.iter();

        let mut queries_values_map = BTreeMap::new();
        let mut hash_layers: Vec<HashMap<usize, Sha256Hash>> = vec![];

        for current_log_size in (0..=max_log_size).rev() {
            queries.sort_unstable();
            queries.dedup();

            if log_sizes_with_data.contains(&current_log_size) {
                // compute the query positions and their siblings
                let mut self_and_siblings = vec![];
                for &q in queries.iter() {
                    self_and_siblings.push(q);
                    self_and_siblings.push(q ^ 1);
                }
                self_and_siblings.sort_unstable();
                self_and_siblings.dedup();

                let mut queries_values = BTreeMap::new();
                for k in self_and_siblings.iter() {
                    let v = [
                        *values_iter.next().unwrap(),
                        *values_iter.next().unwrap(),
                        *values_iter.next().unwrap(),
                        *values_iter.next().unwrap(),
                    ];
                    queries_values.insert(*k, v);
                }

                let mut hash_layer = HashMap::new();
                for (&query, value) in queries_values.iter() {
                    if current_log_size == max_log_size {
                        hash_layer
                            .insert(query, Sha256Poseidon31MerkleHasher::hash_node(None, value));
                    } else {
                        let left_idx = query << 1;
                        let right_idx = left_idx + 1;

                        let left_hash =
                            if let Some(hash) = hash_layers.last().unwrap().get(&left_idx) {
                                *hash
                            } else {
                                let v = *hash_iter.next().unwrap();
                                hash_layers.last_mut().unwrap().insert(left_idx, v);
                                v
                            };
                        let right_hash =
                            if let Some(hash) = hash_layers.last().unwrap().get(&right_idx) {
                                *hash
                            } else {
                                let v = *hash_iter.next().unwrap();
                                hash_layers.last_mut().unwrap().insert(right_idx, v);
                                v
                            };
                        hash_layer.insert(
                            query,
                            Sha256Poseidon31MerkleHasher::hash_node(
                                Some((left_hash, right_hash)),
                                value,
                            ),
                        );
                    }
                }

                queries_values_map.insert(current_log_size, queries_values);
                hash_layers.push(hash_layer);
            } else {
                assert_ne!(current_log_size, max_log_size);

                let mut hash_layer = HashMap::new();
                for &query in queries.iter() {
                    let left_idx = query << 1;
                    let right_idx = left_idx + 1;

                    let left_hash = if let Some(hash) = hash_layers.last().unwrap().get(&left_idx) {
                        *hash
                    } else {
                        let v = *hash_iter.next().unwrap();
                        hash_layers.last_mut().unwrap().insert(left_idx, v);
                        v
                    };
                    let right_hash = if let Some(hash) = hash_layers.last().unwrap().get(&right_idx)
                    {
                        *hash
                    } else {
                        let v = *hash_iter.next().unwrap();
                        hash_layers.last_mut().unwrap().insert(right_idx, v);
                        v
                    };

                    let h =
                        Sha256Poseidon31MerkleHasher::hash_node(Some((left_hash, right_hash)), &[]);
                    hash_layer.insert(query, h);
                }

                hash_layers.push(hash_layer);
            }

            queries.iter_mut().for_each(|v| *v = (*v) >> 1);
        }

        assert!(values_iter.next().is_none());
        assert!(hash_iter.next().is_none());

        assert_eq!(hash_layers.last().unwrap().len(), 1);
        assert_eq!(*hash_layers.last().unwrap().get(&0).unwrap(), root);

        let mut proofs = vec![];
        for leaf_query in leaf_queries.iter() {
            let mut sibling_hashes = vec![];
            let mut self_columns = BTreeMap::new();
            let mut siblings_columns = BTreeMap::new();

            let mut query = *leaf_query;

            for current_log_size in (1..=max_log_size).rev() {
                if log_sizes_with_data.contains(&current_log_size) {
                    let self_idx = query;
                    let sibling_idx = self_idx ^ 1;

                    let self_value = queries_values_map
                        .get(&current_log_size)
                        .unwrap()
                        .get(&self_idx)
                        .unwrap();
                    let sibling_value = queries_values_map
                        .get(&current_log_size)
                        .unwrap()
                        .get(&sibling_idx)
                        .unwrap();

                    self_columns
                        .insert(current_log_size as usize, QM31::from_m31_array(*self_value));
                    siblings_columns.insert(
                        current_log_size as usize,
                        QM31::from_m31_array(*sibling_value),
                    );

                    if current_log_size != max_log_size {
                        let sibling_left = sibling_idx << 1;
                        let sibling_right = sibling_left + 1;

                        let left_hash = *hash_layers
                            [(max_log_size - current_log_size - 1) as usize]
                            .get(&sibling_left)
                            .unwrap();
                        let right_hash = *hash_layers
                            [(max_log_size - current_log_size - 1) as usize]
                            .get(&sibling_right)
                            .unwrap();

                        sibling_hashes.push(Sha256Poseidon31MerkleHasher::hash_node(
                            Some((left_hash, right_hash)),
                            &[],
                        ));
                    }
                } else {
                    let self_idx = query;
                    let sibling_idx = self_idx ^ 1;

                    let sibling_hash = *hash_layers[(max_log_size - current_log_size) as usize]
                        .get(&sibling_idx)
                        .unwrap();
                    sibling_hashes.push(sibling_hash);
                }
                query >>= 1;
            }

            let proof = DelegatedSinglePairMerkleProof {
                query: *leaf_query,
                sibling_hashes,
                self_columns,
                siblings_columns,
                root,
                depth: max_log_size as usize,
            };
            proof.verify();
            proofs.push(proof);
        }
        proofs
    }
}

#[derive(Clone)]
pub struct DelegatedSinglePairMerkleProofBar {
    pub cs: BitcoinSystemRef,
    pub value: DelegatedSinglePairMerkleProof,

    pub sibling_hashes: Vec<Sha256HashBar>,

    pub self_columns: BTreeMap<usize, QM31Bar>,
    pub siblings_columns: BTreeMap<usize, QM31Bar>,
}

impl AllocBar for DelegatedSinglePairMerkleProofBar {
    type Value = DelegatedSinglePairMerkleProof;

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

        let mut self_columns = BTreeMap::new();
        for (k, column) in data.self_columns.iter() {
            self_columns.insert(*k, QM31Bar::new_variable(cs, column.clone(), mode)?);
        }

        let mut siblings_columns = BTreeMap::new();
        for (k, column) in data.siblings_columns.iter() {
            siblings_columns.insert(*k, QM31Bar::new_variable(cs, column.clone(), mode)?);
        }

        Ok(Self {
            cs: cs.clone(),
            value: data.clone(),
            sibling_hashes,
            self_columns,
            siblings_columns,
        })
    }
}

impl DelegatedSinglePairMerkleProofBar {
    pub fn verify(&self, query: &M31Bar, log_size: usize, root: &Sha256HashBar) -> Result<()> {
        let mut bits_vars = split_be_bits(query, log_size)?;
        if log_size > self.sibling_hashes.len() {
            for i in 0..(log_size - self.sibling_hashes.len() - 1) {
                bits_vars[i].drop();
            }
            bits_vars.drain(..(log_size - self.sibling_hashes.len() - 1));
        }

        let cs = query.cs().and(&root.cs());

        let mut self_hash = hash_many_m31(
            &cs,
            &self
                .self_columns
                .get(&self.value.depth)
                .map_or(vec![], |v| v.to_m31_array().to_vec()),
        )?;
        let mut sibling_hash = hash_many_m31(
            &cs,
            &self
                .siblings_columns
                .get(&self.value.depth)
                .map_or(vec![], |v| v.to_m31_array().to_vec()),
        )?;

        for i in 0..self.value.depth {
            let h = self.value.depth - i - 1;

            if !self.self_columns.contains_key(&h) {
                self_hash = hash_node(&self_hash, &sibling_hash, &bits_vars[i], None)?;
                if i != self.value.depth - 1 {
                    sibling_hash = self.sibling_hashes[i].clone();
                }
            } else {
                self_hash = hash_node(
                    &self_hash,
                    &sibling_hash,
                    &bits_vars[i],
                    Some(self.self_columns.get(&h).unwrap()),
                )?;

                let mut hash = self.sibling_hashes[i].value;
                let m31 = self.siblings_columns.get(&h).unwrap().to_m31_array();
                for v in m31.iter() {
                    let mut sha256 = Sha256::new();
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(v.value));
                    Digest::update(&mut sha256, hash);
                    hash = Sha256Hash::from(sha256.finalize().as_slice());
                }
                cs.insert_script(
                    hash_column_upon_hash,
                    [
                        m31[3].variable,
                        m31[2].variable,
                        m31[1].variable,
                        m31[0].variable,
                        self.sibling_hashes[i].variable,
                    ],
                )?;
                sibling_hash = Sha256HashBar::new_function_output(&cs, hash)?;
            }
        }
        self_hash.equalverify(&root)
    }
}

pub fn hash_node(
    self_hash: &Sha256HashBar,
    sibling_hash: &Sha256HashBar,
    bit: &BoolBar,
    data: Option<&QM31Bar>,
) -> Result<Sha256HashBar> {
    let mut cs = self_hash.cs().and(&sibling_hash.cs()).and(&bit.cs());
    let mut hash = [0u8; 32];

    if !bit.value {
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, self_hash.value);
        Digest::update(&mut sha256, sibling_hash.value);
        hash.copy_from_slice(sha256.finalize().as_slice());
    } else {
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, sibling_hash.value);
        Digest::update(&mut sha256, self_hash.value);
        hash.copy_from_slice(sha256.finalize().as_slice());
    }

    if data.is_none() {
        cs.insert_script(
            hash_node_no_column,
            [self_hash.variable, sibling_hash.variable, bit.variable],
        )?;
        Sha256HashBar::new_function_output(&cs, Sha256Hash::from(hash.as_slice()))
    } else {
        let data = data.unwrap();
        cs = cs.and(&data.cs());
        let m31 = data.to_m31_array();
        for v in m31.iter() {
            let mut sha256 = Sha256::new();
            Digest::update(&mut sha256, bitcoin_num_to_bytes(v.value));
            Digest::update(&mut sha256, hash);
            hash.copy_from_slice(sha256.finalize().as_slice());
        }
        cs.insert_script(
            hash_node_with_column,
            [
                m31[3].variable,
                m31[2].variable,
                m31[1].variable,
                m31[0].variable,
                self_hash.variable,
                sibling_hash.variable,
                bit.variable,
            ],
        )?;
        Sha256HashBar::new_function_output(&cs, Sha256Hash::from(hash.as_slice()))
    }
}

fn hash_node_no_column() -> Script {
    script! {
        OP_IF OP_SWAP OP_ENDIF
        OP_CAT OP_SHA256
    }
}

fn hash_node_with_column() -> Script {
    script! {
        hash_node_no_column
        hash_column_upon_hash
    }
}

fn hash_column_upon_hash() -> Script {
    script! {
        for _ in 0..4 {
            OP_CAT OP_SHA256
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedFirstLayerHints {
    pub merkle_proofs: Vec<DelegatedSinglePairMerkleProof>,
    pub folded_evals_by_column: BTreeMap<u32, Vec<SecureField>>,
}

impl DelegatedFirstLayerHints {
    pub fn compute(
        fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
        answer_hints: &AnswerHints<Sha256Poseidon31MerkleChannel>,
        proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    ) -> DelegatedFirstLayerHints {
        // Columns are provided in descending order by size.
        let max_column_log_size = fiat_shamir_hints
            .fri_verifier
            .first_layer
            .column_commitment_domains[0]
            .log_size();
        assert_eq!(
            fiat_shamir_hints.max_first_layer_column_log_size,
            max_column_log_size
        );

        let mut fri_witness = proof
            .stark_proof
            .fri_proof
            .first_layer
            .fri_witness
            .iter()
            .copied();

        let mut decommitment_positions_by_log_size = BTreeMap::new();
        let mut decommitmented_values = vec![];

        let mut folded_evals_by_column = BTreeMap::new();

        for (&column_domain, column_query_evals) in zip_eq(
            &fiat_shamir_hints
                .fri_verifier
                .first_layer
                .column_commitment_domains,
            &answer_hints.fri_answers,
        ) {
            let queries =
                &fiat_shamir_hints.sorted_query_positions_per_log_size[&column_domain.log_size()];

            let (column_decommitment_positions, sparse_evaluation) =
                Self::compute_decommitment_positions_and_rebuild_evals(
                    queries,
                    column_domain.log_size(),
                    &column_query_evals,
                    &mut fri_witness,
                );

            // Columns of the same size have the same decommitment positions.
            decommitment_positions_by_log_size
                .insert(column_domain.log_size(), column_decommitment_positions);

            decommitmented_values.extend(
                sparse_evaluation
                    .subset_evals
                    .iter()
                    .flatten()
                    .flat_map(|qm31| qm31.to_m31_array()),
            );
            folded_evals_by_column.insert(
                column_domain.log_size(),
                sparse_evaluation.fold_circle(
                    fiat_shamir_hints.fri_alphas
                        [(max_column_log_size - column_domain.log_size()) as usize],
                    column_domain,
                ),
            );
        }

        assert!(fri_witness.next().is_none());

        let merkle_verifier = MerkleVerifier::new(
            proof.stark_proof.fri_proof.first_layer.commitment,
            fiat_shamir_hints
                .fri_verifier
                .first_layer
                .column_commitment_domains
                .iter()
                .flat_map(|column_domain| [column_domain.log_size(); SECURE_EXTENSION_DEGREE])
                .collect(),
        );

        merkle_verifier
            .verify(
                &decommitment_positions_by_log_size,
                decommitmented_values.clone(),
                proof.stark_proof.fri_proof.first_layer.decommitment.clone(),
            )
            .unwrap();

        // log_sizes with data
        let mut log_sizes_with_data = BTreeSet::new();
        for column_domain in fiat_shamir_hints
            .fri_verifier
            .first_layer
            .column_commitment_domains
            .iter()
        {
            log_sizes_with_data.insert(column_domain.log_size());
        }

        let merkle_proofs = DelegatedSinglePairMerkleProof::from_stwo_proof(
            &log_sizes_with_data,
            proof.stark_proof.fri_proof.first_layer.commitment,
            &fiat_shamir_hints
                .unsorted_query_positions_per_log_size
                .get(&fiat_shamir_hints.max_first_layer_column_log_size)
                .unwrap(),
            &decommitmented_values,
            &proof.stark_proof.fri_proof.first_layer.decommitment,
        );
        for proof in merkle_proofs.iter() {
            proof.verify();
        }

        DelegatedFirstLayerHints {
            merkle_proofs,
            folded_evals_by_column,
        }
    }

    pub fn compute_decommitment_positions_and_rebuild_evals(
        queries: &[usize],
        domain_log_size: u32,
        query_evals: &[SecureField],
        mut witness_evals: impl Iterator<Item = SecureField>,
    ) -> (Vec<usize>, SparseEvaluation) {
        let mut queries = queries.to_vec();
        queries.dedup();
        queries.sort_unstable();

        let mut query_evals = query_evals.iter().copied();

        let mut decommitment_positions = Vec::new();
        let mut subset_evals = Vec::new();
        let mut subset_domain_index_initials = Vec::new();

        // Group queries by the subset they reside in.
        for subset_queries in queries.chunk_by(|a, b| a >> 1 == b >> 1) {
            let subset_start = (subset_queries[0] >> 1) << 1;
            let subset_decommitment_positions = subset_start..subset_start + (1 << 1);
            decommitment_positions.extend(subset_decommitment_positions.clone());

            let mut subset_queries_iter = subset_queries.iter().copied().peekable();

            let subset_eval = subset_decommitment_positions
                .map(|position| match subset_queries_iter.next_if_eq(&position) {
                    Some(_) => query_evals.next().unwrap(),
                    None => witness_evals.next().unwrap(),
                })
                .collect_vec();

            subset_evals.push(subset_eval.clone());
            subset_domain_index_initials.push(bit_reverse_index(subset_start, domain_log_size));
        }

        let sparse_evaluation = SparseEvaluation::new(subset_evals, subset_domain_index_initials);
        (decommitment_positions, sparse_evaluation)
    }
}

#[derive(Clone)]
pub struct DelegatedFirstLayerBar {
    pub value: DelegatedFirstLayerHints,
    pub merkle_proofs: Vec<DelegatedSinglePairMerkleProofBar>,
}

impl AllocBar for DelegatedFirstLayerBar {
    type Value = DelegatedFirstLayerHints;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value.clone())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut merkle_proofs = vec![];
        for proof in data.merkle_proofs.iter() {
            merkle_proofs.push(DelegatedSinglePairMerkleProofBar::new_variable(
                cs,
                proof.clone(),
                mode,
            )?);
        }
        Ok(Self {
            value: data,
            merkle_proofs,
        })
    }
}

impl DelegatedFirstLayerBar {
    pub fn verify(
        &self,
        queries: &[M31Bar],
        log_size: usize,
        commitment_var: &Sha256HashBar,
    ) -> Result<()> {
        for (proof, query) in self.merkle_proofs.iter().zip(queries) {
            proof.verify(query, log_size, commitment_var)?;
        }
        Ok(())
    }

    pub fn input_elements(&self) -> Result<Vec<QM31Bar>> {
        let mut results = vec![];
        for proof in self.merkle_proofs.iter() {
            for (_, elem) in proof.self_columns.iter() {
                results.push(elem.clone());
            }
            for (_, elem) in proof.siblings_columns.iter() {
                results.push(elem.clone());
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod test {
    use crate::folding::{DelegatedFirstLayerBar, DelegatedFirstLayerHints};
    use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
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
    fn test_first_layer() {
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
        let fri_answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
        let first_layer_hints =
            DelegatedFirstLayerHints::compute(&fiat_shamir_hints, &fri_answer_hints, &proof);

        let cs = BitcoinSystemRef::new_ref();
        let first_layer_var = DelegatedFirstLayerBar::new_hint(&cs, first_layer_hints).unwrap();

        let mut queries_vars = vec![];
        for query in fiat_shamir_hints.unsorted_query_positions_per_log_size
            [&fiat_shamir_hints.max_first_layer_column_log_size]
            .iter()
        {
            queries_vars.push(M31Bar::new_hint(&cs, M31::from(*query)).unwrap());
        }

        let first_layer_commitment_var =
            Sha256HashBar::new_hint(&cs, fiat_shamir_hints.first_layer_commitment).unwrap();

        first_layer_var
            .verify(
                &queries_vars,
                fiat_shamir_hints.max_first_layer_column_log_size as usize,
                &first_layer_commitment_var,
            )
            .unwrap();

        let _ = first_layer_var.input_elements().unwrap();
        test_program(cs, script! {}).unwrap();
    }
}
