use std::sync::OnceLock;
use recursive_stwo_bitcoin_dsl::treepp::*;

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