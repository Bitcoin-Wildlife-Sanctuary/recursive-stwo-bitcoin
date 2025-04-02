use crate::folding::merkle_proofs::{
    DelegatedSinglePairMerkleProof, DelegatedSinglePairMerkleProofBar,
};
use anyhow::Result;
use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
use itertools::{zip_eq, Itertools};
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_prover::core::fri::SparseEvaluation;
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::core::vcs::verifier::MerkleVerifier;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

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
    use crate::folding::first_layer::{DelegatedFirstLayerBar, DelegatedFirstLayerHints};
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
