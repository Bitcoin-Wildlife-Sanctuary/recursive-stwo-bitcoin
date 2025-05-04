use anyhow::Result;
use bitcoin::script::write_scriptint;
use bitcoin_scriptexec::utils::scriptint_vec;
use circle_plonk_dsl_hints::{AnswerHints, FiatShamirHints};
use covenants_gadgets::utils::pseudo::OP_HINT;
use covenants_gadgets::utils::stack_hash::StackHash;
use covenants_gadgets::CovenantProgram;
use num_traits::One;
use recursive_stwo_bitcoin_dsl::bitcoin_system::{BitcoinSystemRef, Element};
use recursive_stwo_bitcoin_dsl::compiler::Compiler;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_bitcoin_dsl::treepp::*;
use recursive_stwo_delegation::folding::{DelegatedFirstLayerHints, DelegatedInnerLayersHints};
use recursive_stwo_delegation::script::{
    compute_delegation_inputs, compute_input_labels, part1, part2, part3, part4, part5,
};
use recursive_stwo_last::script::global::part12_line_coeffs::generate_oods_shifted_logsize_26_labels;
use recursive_stwo_last::script::global::part13_line_coeffs::{
    generate_oods_original_logsize_26_labels, generate_oods_original_logsize_28_labels,
};
use recursive_stwo_last::script::global::{
    part10_logup, part11_point_shift, part12_line_coeffs, part13_line_coeffs, part14_line_coeffs,
    part1_fiat_shamir, part2_input_sum, part3_fiat_shamir, part4_composition, part5_composition,
    part6_composition, part7_coset_vanishing, part8_coset_vanishing, part9_coset_vanishing,
};
use recursive_stwo_last::script::hints::answer::LastAnswerHints;
use recursive_stwo_last::script::hints::decommit::LastDecommitHints;
use recursive_stwo_last::script::hints::fiat_shamir::LastFiatShamirHints;
use recursive_stwo_last::script::hints::folding::{LastFirstLayerHints, LastInnerLayersHints};
use recursive_stwo_last::script::part_last;
use recursive_stwo_last::script::per_query::{
    part10_folding, part11_folding, part12_folding, part13_clear, part1_domain_point,
    part2_numerator, part3_numerator, part4_numerator, part5_numerator, part6_numerator,
    part7_numerator, part8_fri_decommitment, part9_folding,
};
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::core::vcs::sha256_poseidon31_merkle::{
    Sha256Poseidon31MerkleChannel, Sha256Poseidon31MerkleHasher,
};
use stwo_prover::examples::plonk_with_poseidon::air::{
    verify_plonk_with_poseidon, PlonkWithPoseidonProof,
};
use stwo_prover::examples::plonk_without_poseidon::air::{
    verify_plonk_without_poseidon, PlonkWithoutPoseidonProof,
};

pub static RECURSIVE_STWO_ALL_INFORMATION: OnceLock<RecursiveStwoAllInformation> = OnceLock::new();

pub type Witness = Vec<Vec<u8>>;
pub struct RecursiveStwoAllInformation {
    pub scripts: Vec<Script>,
    pub witnesses: Vec<Witness>,
    pub outputs: Vec<Witness>,
}

#[derive(Clone)]
pub struct RecursiveStwoVerifierInput {
    pub stack: Witness,
    pub hints: Witness,
}

/// The state of the split program.
#[derive(Clone, Debug)]
pub struct RecursiveStwoVerifierState {
    /// The program counter.
    pub pc: usize,
    /// The hash of the stack.
    pub stack_hash: Vec<u8>,
    /// The stack from the execution.
    pub stack: Vec<Vec<u8>>,
}

impl From<RecursiveStwoVerifierState> for Script {
    fn from(v: RecursiveStwoVerifierState) -> Self {
        script! {
            { v.pc }
            { v.stack_hash }
        }
    }
}

impl From<RecursiveStwoVerifierInput> for Script {
    fn from(input: RecursiveStwoVerifierInput) -> Script {
        script! {
            for elem in input.stack {
                { elem }
            }
            for elem in input.hints {
                { elem }
            }
        }
    }
}

impl RecursiveStwoAllInformation {
    pub fn get_input(&self, idx: usize) -> RecursiveStwoVerifierInput {
        RecursiveStwoVerifierInput {
            stack: if idx == 0 {
                vec![]
            } else {
                self.outputs[idx - 1].clone()
            },
            hints: self.witnesses[idx].clone(),
        }
    }
}

pub fn push_delegated_information(
    scripts: &mut Vec<Script>,
    witnesses: &mut Vec<Vec<Vec<u8>>>,
    outputs: &mut Vec<Vec<Vec<u8>>>,
    proof: &PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher>,
    config: PcsConfig,
) -> LDM {
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
    let inner_layers_hints = DelegatedInnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );

    let mut ldm_delegated = LDM::new();

    let mut add_cs = |cs: BitcoinSystemRef, ldm: &LDM| {
        let program = Compiler::compile(cs).unwrap();

        scripts.push(program.script);

        let mut witness = vec![];
        for entry in program.hint.iter() {
            match &entry {
                Element::Num(v) => {
                    witness.push(num_to_str(*v));
                }
                Element::Str(v) => {
                    witness.push(v.clone());
                }
            }
        }

        witnesses.push(witness);
        outputs.push(
            convert_to_witness(script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            })
            .unwrap(),
        );
    };

    let cs = part1::generate_cs(&fiat_shamir_hints, &proof, config, &mut ldm_delegated).unwrap();
    add_cs(cs, &ldm_delegated);

    let cs = part2::generate_cs(
        &fiat_shamir_hints,
        &proof,
        &first_layer_hints,
        &mut ldm_delegated,
    )
    .unwrap();
    add_cs(cs, &ldm_delegated);

    let cs =
        part3::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    add_cs(cs, &ldm_delegated);

    let cs =
        part4::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    add_cs(cs, &ldm_delegated);

    let cs =
        part5::generate_cs(&fiat_shamir_hints, &inner_layers_hints, &mut ldm_delegated).unwrap();
    add_cs(cs, &ldm_delegated);

    ldm_delegated
}

pub fn push_last_information(
    scripts: &mut Vec<Script>,
    witnesses: &mut Vec<Vec<Vec<u8>>>,
    outputs: &mut Vec<Vec<Vec<u8>>>,
    proof_last: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    config_last: PcsConfig,
    inputs: &[(usize, QM31)],
    mut ldm: LDM,
) {
    verify_plonk_without_poseidon::<Sha256MerkleChannel>(proof_last.clone(), config_last, &inputs)
        .unwrap();

    let last_fiat_shamir_hints =
        LastFiatShamirHints::<Sha256MerkleChannel>::new(&proof_last, config_last, &inputs);
    let last_decommit_preprocessed_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 0);
    let last_decommit_trace_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 1);
    let last_decommit_interaction_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 2);
    let last_decommit_composition_hints =
        LastDecommitHints::compute(&last_fiat_shamir_hints, &proof_last, 3);
    let last_answer_hints = LastAnswerHints::compute(&last_fiat_shamir_hints, &proof_last);
    let last_first_layer_hints =
        LastFirstLayerHints::compute(&last_fiat_shamir_hints, &last_answer_hints, &proof_last);
    let last_inner_layers_hints = LastInnerLayersHints::compute(
        &last_first_layer_hints.folded_evals_by_column,
        &last_fiat_shamir_hints,
        &proof_last,
    );

    let mut add_cs = |cs: BitcoinSystemRef, ldm: &LDM, ldm_per_query: Option<&LDM>| {
        let program = Compiler::compile(cs).unwrap();

        scripts.push(program.script);

        let mut witness = vec![];
        for entry in program.hint.iter() {
            match &entry {
                Element::Num(v) => {
                    witness.push(num_to_str(*v));
                }
                Element::Str(v) => {
                    witness.push(v.clone());
                }
            }
        }

        witnesses.push(witness);
        if let Some(ldm_per_query) = ldm_per_query {
            outputs.push(
                convert_to_witness(script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                    { ldm_per_query.hash_var.as_ref().unwrap().value.clone() }
                })
                .unwrap(),
            );
        } else {
            outputs.push(
                convert_to_witness(script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                })
                .unwrap(),
            );
        }
    };

    let cs = part1_fiat_shamir::generate_cs(&proof_last, &mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let input_labels = compute_input_labels();
    for counter in 0..39 {
        let cs = part2_input_sum::generate_cs(&mut ldm, counter, &input_labels).unwrap();
        add_cs(cs, &ldm, None);
    }

    let cs =
        part3_fiat_shamir::generate_cs(&last_fiat_shamir_hints, &proof_last, config_last, &mut ldm)
            .unwrap();
    add_cs(cs, &ldm, None);

    let cs = part4_composition::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part5_composition::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part6_composition::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part7_coset_vanishing::generate_cs(&proof_last, &mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part8_coset_vanishing::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part9_coset_vanishing::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part10_logup::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let cs = part11_point_shift::generate_cs(&proof_last, &mut ldm).unwrap();
    add_cs(cs, &ldm, None);

    let oods_shifted_logsize_26_labels = generate_oods_shifted_logsize_26_labels();
    for counter in 0..2 {
        let cs =
            part12_line_coeffs::generate_cs(&mut ldm, counter, &oods_shifted_logsize_26_labels)
                .unwrap();
        add_cs(cs, &ldm, None);
    }

    let oods_original_logsize_26_labels = generate_oods_original_logsize_26_labels();
    for counter in 0..12 {
        let cs =
            part13_line_coeffs::generate_cs(&mut ldm, counter, &oods_original_logsize_26_labels)
                .unwrap();
        add_cs(cs, &ldm, None);
    }

    let oods_original_logsize_28_labels = generate_oods_original_logsize_28_labels();
    for counter in 0..2 {
        let cs =
            part14_line_coeffs::generate_cs(&mut ldm, counter, &oods_original_logsize_28_labels)
                .unwrap();
        add_cs(cs, &ldm, None);
    }

    for query_idx in 0..8 {
        let mut ldm_per_query = LDM::new();
        let cs = part1_domain_point::generate_cs(
            query_idx,
            &last_decommit_composition_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part2_numerator::generate_cs(
            query_idx,
            &last_decommit_preprocessed_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part3_numerator::generate_cs(
            query_idx,
            &last_decommit_trace_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part4_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part5_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part6_numerator::generate_cs(
            query_idx,
            &last_decommit_interaction_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part7_numerator::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part8_fri_decommitment::generate_cs(
            query_idx,
            &last_first_layer_hints,
            &last_inner_layers_hints,
            &mut ldm,
            &mut ldm_per_query,
        )
        .unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part9_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part10_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part11_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part12_folding::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, Some(&ldm_per_query));

        let cs = part13_clear::generate_cs(&mut ldm, &mut ldm_per_query).unwrap();
        add_cs(cs, &ldm, None);
    }

    let cs = part_last::generate_cs(&mut ldm).unwrap();
    add_cs(cs, &ldm, None);
}

pub fn compute_all_information() -> RecursiveStwoAllInformation {
    let proof: PlonkWithPoseidonProof<Sha256Poseidon31MerkleHasher> =
        bincode::deserialize(include_bytes!("../../data/hybrid_hash.bin")).unwrap();
    let config = PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    };
    let proof_last: PlonkWithoutPoseidonProof<Sha256MerkleHasher> =
        bincode::deserialize(include_bytes!("../../data/bitcoin_proof.bin")).unwrap();
    let config_last = PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(0, 9, 8),
    };

    let mut scripts = vec![];
    let mut witnesses = vec![];
    let mut outputs = vec![];

    let ldm =
        push_delegated_information(&mut scripts, &mut witnesses, &mut outputs, &proof, config);
    let inputs = compute_delegation_inputs(&proof, config);
    push_last_information(
        &mut scripts,
        &mut witnesses,
        &mut outputs,
        &proof_last,
        config_last,
        &inputs,
        ldm,
    );

    assert_eq!(scripts.len(), witnesses.len());
    assert_eq!(scripts.len(), outputs.len());

    RecursiveStwoAllInformation {
        scripts,
        witnesses,
        outputs,
    }
}

fn num_to_str(v: i32) -> Vec<u8> {
    let mut out = [0u8; 8];
    let len = write_scriptint(&mut out, v as i64);
    out[0..len].to_vec()
}

pub struct RecursiveStwoVerifierProgram {}

impl CovenantProgram for RecursiveStwoVerifierProgram {
    type State = RecursiveStwoVerifierState;

    type Input = RecursiveStwoVerifierInput;

    const CACHE_NAME: &'static str = "RECURSIVE_STWO";

    fn new() -> Self::State {
        RecursiveStwoVerifierState {
            pc: 0,
            stack_hash: vec![0u8; 32],
            stack: vec![],
        }
    }

    fn get_hash(state: &Self::State) -> Vec<u8> {
        assert_eq!(state.stack_hash.len(), 32);
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, &scriptint_vec(state.pc as i64));
        Update::update(&mut sha256, &state.stack_hash);
        sha256.finalize().to_vec()
    }

    fn get_all_scripts() -> BTreeMap<usize, Script> {
        let all_information = RECURSIVE_STWO_ALL_INFORMATION.get_or_init(compute_all_information);

        let mut map = BTreeMap::new();
        let num_scripts = all_information.scripts.len();
        println!("num_scripts: {}", num_scripts);

        for script_idx in 0..num_scripts {
            map.insert(
                script_idx,
                script! {
                    // input:
                    // - old pc
                    // - old stack hash
                    // - new pc
                    // - new stack hash

                    OP_SWAP { script_idx + 1 } OP_EQUALVERIFY
                    OP_ROT { script_idx } OP_EQUALVERIFY

                    if script_idx == 0 {
                        OP_SWAP { vec![0u8; 32] } OP_EQUALVERIFY

                        // stack:
                        // - new stack hash
                        OP_TOALTSTACK
                    } else {
                        // stack:
                        // - old stack hash
                        // - new stack hash
                        OP_TOALTSTACK OP_TOALTSTACK

                        { StackHash::hash_from_hint(all_information.outputs[script_idx - 1].len()) }
                        OP_FROMALTSTACK OP_EQUALVERIFY
                    }

                    { all_information.scripts[script_idx].clone() }

                    OP_DEPTH
                    { all_information.outputs[script_idx].len() }
                    OP_EQUALVERIFY

                    { StackHash::hash_drop(all_information.outputs[script_idx].len()) }
                    OP_FROMALTSTACK OP_EQUALVERIFY
                    OP_TRUE
                },
            );
        }

        map
    }

    fn get_common_prefix() -> Script {
        script! {
            // hint:
            // - old_state
            // - new_state
            //
            // input:
            // - old_state_hash
            // - new_state_hash
            //
            // output:
            // - old pc
            // - old stack hash
            // - new pc
            // - new stack hash
            //

            OP_TOALTSTACK OP_TOALTSTACK

            for _ in 0..2 {
                OP_HINT OP_1ADD OP_1SUB OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_HINT OP_SIZE 32 OP_EQUALVERIFY

                OP_2DUP
                OP_CAT
                OP_SHA256
                OP_FROMALTSTACK OP_EQUALVERIFY
            }
        }
    }

    fn run(id: usize, _: &Self::State, _: &Self::Input) -> Result<Self::State> {
        let all_information = RECURSIVE_STWO_ALL_INFORMATION.get_or_init(compute_all_information);

        let final_stack = all_information.outputs[id].clone();
        let stack_hash = StackHash::compute(&final_stack);
        Ok(Self::State {
            pc: id + 1,
            stack_hash,
            stack: final_stack,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        compute_all_information, RecursiveStwoVerifierProgram, RecursiveStwoVerifierState,
        RECURSIVE_STWO_ALL_INFORMATION,
    };
    use bitcoin_simulator::policy::Policy;
    use covenants_gadgets::test::{simulation_test_with_policy, SimulationInstruction};

    #[test]
    fn test_covenant() {
        let all_information = RECURSIVE_STWO_ALL_INFORMATION.get_or_init(compute_all_information);
        let mut test_generator = |old_state: &RecursiveStwoVerifierState| {
            Some(SimulationInstruction {
                program_index: old_state.pc,
                program_input: all_information.get_input(old_state.pc),
            })
        };
        let policy = Policy::default().set_fee(1).set_max_tx_weight(400000);
        let total_fee = simulation_test_with_policy::<RecursiveStwoVerifierProgram>(
            all_information.outputs.len(),
            &mut test_generator,
            &policy,
        );
        println!("total_fee: {:?} sats", total_fee);
    }
}
