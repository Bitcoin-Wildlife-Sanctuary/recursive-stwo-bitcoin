use crate::folding::merkle_proofs::{
    DelegatedSinglePairMerkleProof, DelegatedSinglePairMerkleProofBar,
};
use anyhow::Result;
use circle_plonk_dsl_hints::FiatShamirHints;
use itertools::Itertools;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_prover::core::fields::{ExtensionOf, Field, FieldExpOps};
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::core::vcs::verifier::MerkleVerifier;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedInnerLayersHints {
    pub merkle_proofs: BTreeMap<u32, Vec<DelegatedSinglePairMerkleProof>>,
    pub folded_intermediate_results: BTreeMap<u32, BTreeMap<usize, SecureField>>,
}

impl DelegatedInnerLayersHints {
    pub fn compute(
        folded_evals_by_column: &BTreeMap<u32, Vec<SecureField>>,
        fiat_shamir_hints: &FiatShamirHints<Sha256Poseidon31MerkleChannel>,
        proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    ) -> DelegatedInnerLayersHints {
        let mut log_size = fiat_shamir_hints.max_first_layer_column_log_size;

        let mut folded = BTreeMap::new();
        for i in fiat_shamir_hints
            .unsorted_query_positions_per_log_size
            .get(&log_size)
            .unwrap()
            .iter()
            .map(|v| (*v) >> 1)
        {
            folded.insert(i, QM31::zero());
        }

        let mut all_merkle_proofs = BTreeMap::new();
        let mut all_folded_intermediate_results = BTreeMap::new();

        for (i, inner_layer) in proof.stark_proof.fri_proof.inner_layers.iter().enumerate() {
            if let Some(folded_into) = folded_evals_by_column.get(&log_size) {
                assert_eq!(folded_into.len(), folded.len());
                for ((_, v), b) in folded.iter_mut().zip(folded_into.iter()) {
                    *v = fiat_shamir_hints.fri_alphas[i].square() * *v + *b;
                }
            }

            log_size -= 1;

            let domain = Coset::half_odds(log_size);

            let mut fri_witness = inner_layer.fri_witness.iter();
            let mut new_folded = BTreeMap::new();
            let mut decommitmented = BTreeMap::new();

            for (k, &v) in folded.iter() {
                let sibling_v = if let Some(&sibling_v) = folded.get(&(k ^ 1)) {
                    sibling_v
                } else {
                    *fri_witness.next().unwrap()
                };

                let (left_v, right_v) = if k & 1 == 0 {
                    (v, sibling_v)
                } else {
                    (sibling_v, v)
                };

                let folded_query = k >> 1;
                let left_idx = folded_query << 1;
                let right_idx = left_idx + 1;

                decommitmented.insert(left_idx, left_v);
                decommitmented.insert(right_idx, right_v);

                let point = domain.at(bit_reverse_index(left_idx, log_size));
                let x_inv = point.x.inverse();

                let new_left_v = left_v + right_v;
                let new_right_v = (left_v - right_v) * x_inv;
                let folded_value = new_left_v + new_right_v * fiat_shamir_hints.fri_alphas[i + 1];

                new_folded.insert(folded_query, folded_value);
            }

            let decommitment_positions = decommitmented.keys().copied().collect_vec();
            let decommitmented_values = decommitmented
                .values()
                .map(|v| v.to_m31_array())
                .flatten()
                .collect_vec();

            let merkle_verifier: MerkleVerifier<Sha256Poseidon31MerkleHasher> = MerkleVerifier::new(
                inner_layer.commitment,
                vec![log_size; SECURE_EXTENSION_DEGREE],
            );
            merkle_verifier
                .verify(
                    &BTreeMap::from_iter([(log_size, decommitment_positions)]),
                    decommitmented_values.clone(),
                    inner_layer.decommitment.clone(),
                )
                .unwrap();

            let merkle_proofs = DelegatedSinglePairMerkleProof::from_stwo_proof(
                &BTreeSet::from([log_size]),
                inner_layer.commitment.clone(),
                &fiat_shamir_hints
                    .unsorted_query_positions_per_log_size
                    .get(&fiat_shamir_hints.max_first_layer_column_log_size)
                    .unwrap()
                    .iter()
                    .map(|v| *v >> (fiat_shamir_hints.max_first_layer_column_log_size - log_size))
                    .collect_vec(),
                &decommitmented_values,
                &inner_layer.decommitment,
            );
            for merkle_proof in merkle_proofs.iter() {
                merkle_proof.verify();
            }
            all_merkle_proofs.insert(log_size, merkle_proofs);

            assert!(fri_witness.next().is_none());
            all_folded_intermediate_results.insert(log_size, folded.clone());
            folded = new_folded;
        }

        log_size -= 1;
        let domain = Coset::half_odds(log_size);
        for (&idx, v) in folded.iter() {
            let mut x = domain.at(bit_reverse_index(idx, log_size)).x;
            let last_poly_log_size = fiat_shamir_hints.last_layer_coeffs.len().ilog2();
            let mut doublings = Vec::new();
            for _ in 0..last_poly_log_size {
                doublings.push(x);
                x = CirclePoint::<M31>::double_x(x);
            }

            pub fn fold<F: Field, E: ExtensionOf<F>>(values: &[E], folding_factors: &[F]) -> E {
                let n = values.len();
                assert_eq!(n, 1 << folding_factors.len());
                if n == 1 {
                    return values[0].into();
                }
                let (lhs_values, rhs_values) = values.split_at(n / 2);
                let (folding_factor, folding_factors) = folding_factors.split_first().unwrap();
                let lhs_val = fold(lhs_values, folding_factors);
                let rhs_val = fold(rhs_values, folding_factors);
                lhs_val + rhs_val * *folding_factor
            }

            let res = fold(&fiat_shamir_hints.last_layer_coeffs, &doublings);
            assert_eq!(*v, res);
        }

        Self {
            merkle_proofs: all_merkle_proofs,
            folded_intermediate_results: all_folded_intermediate_results,
        }
    }
}

#[derive(Clone)]
pub struct DelegatedInnerLayersPerLayerBar {
    pub merkle_proofs: Vec<DelegatedSinglePairMerkleProofBar>,
}

impl AllocBar for DelegatedInnerLayersPerLayerBar {
    type Value = Vec<DelegatedSinglePairMerkleProof>;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.merkle_proofs.iter().map(|v| v.value.clone()).collect())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut merkle_proofs = vec![];
        for proof in data.iter() {
            merkle_proofs.push(DelegatedSinglePairMerkleProofBar::new_variable(
                cs,
                proof.clone(),
                mode,
            )?);
        }
        Ok(Self { merkle_proofs })
    }
}

impl DelegatedInnerLayersPerLayerBar {
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
