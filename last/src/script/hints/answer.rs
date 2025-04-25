use crate::script::hints::fiat_shamir::LastFiatShamirHints;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::iter::zip;
use std::marker::PhantomData;
use stwo_prover::core::channel::MerkleChannel;
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::pcs::quotients::{fri_answers, PointSample};
use stwo_prover::core::ColumnVec;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

#[derive(Debug, Default)]
pub struct SampledValuesPerLogSize(pub BTreeMap<u32, ColumnVec<BaseField>>);
#[derive(Debug, Default)]
pub struct SampledValues(pub BTreeMap<u32, SampledValuesPerLogSize>);

pub struct LastAnswerHints<MC: MerkleChannel> {
    pub fri_answers: ColumnVec<Vec<SecureField>>,
    pub sampled_values: SampledValues,
    pub phantom: PhantomData<MC>,
}

impl<MC: MerkleChannel> LastAnswerHints<MC> {
    pub fn compute(
        fiat_shamir_hints: &LastFiatShamirHints<MC>,
        proof: &PlonkWithoutPoseidonProof<MC::H>,
    ) -> Self {
        // Answer FRI queries.
        let samples = fiat_shamir_hints
            .sample_points
            .clone()
            .zip_cols(proof.stark_proof.sampled_values.clone())
            .map_cols(|(sampled_points, sampled_values)| {
                zip(sampled_points, sampled_values)
                    .map(|(point, value)| PointSample { point, value })
                    .collect_vec()
            });

        let fri_answers = fri_answers(
            fiat_shamir_hints.column_log_sizes.clone(),
            samples,
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.sorted_query_positions_per_log_size,
            proof.stark_proof.queried_values.clone(),
            fiat_shamir_hints.n_columns_per_log_size.as_ref(),
        )
        .unwrap();

        let mut sampled_values = SampledValues::default();
        let mut queried_values = proof
            .stark_proof
            .queried_values
            .clone()
            .map(|values| values.into_iter());

        let _ = fiat_shamir_hints
            .all_log_sizes
            .iter()
            .rev()
            .for_each(|log_size| {
                let mut sampled_values_per_log_size = SampledValuesPerLogSize::default();

                let n_columns = fiat_shamir_hints
                    .n_columns_per_log_size
                    .as_ref()
                    .map(|colums_log_sizes| *colums_log_sizes.get(log_size).unwrap_or(&0));
                for query_position in
                    fiat_shamir_hints.sorted_query_positions_per_log_size[log_size].iter()
                {
                    let queried_values_at_row = queried_values
                        .as_mut()
                        .zip_eq(n_columns.as_ref())
                        .map(|(queried_values, n_columns)| {
                            queried_values.take(*n_columns).collect()
                        })
                        .flatten();
                    sampled_values_per_log_size
                        .0
                        .insert(*query_position as u32, queried_values_at_row);
                }
                sampled_values
                    .0
                    .insert(*log_size, sampled_values_per_log_size);
            });

        Self {
            sampled_values,
            fri_answers,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::script::hints::answer::LastAnswerHints;
    use crate::script::hints::fiat_shamir::LastFiatShamirHints;
    use recursive_stwo_delegation::script::compute_delegation_inputs;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
    use stwo_prover::core::vcs::sha256_poseidon31_merkle::Sha256Poseidon31MerkleHasher;
    use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;
    use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

    #[test]
    fn test_compute_fri_answer_hints() {
        let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../../data/hybrid_hash.bin")).unwrap();
        let config = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(7, 9, 8),
        };

        let inputs = compute_delegation_inputs(&proof, config);

        let proof_last: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
            bincode::deserialize(include_bytes!("../../../../data/bitcoin_proof.bin")).unwrap();
        let config_last = PcsConfig {
            pow_bits: 28,
            fri_config: FriConfig::new(0, 9, 8),
        };

        let last_fiat_shamir_hints =
            LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);
        let _ = LastAnswerHints::compute(&last_fiat_shamir_hints, &proof_last);
    }
}
