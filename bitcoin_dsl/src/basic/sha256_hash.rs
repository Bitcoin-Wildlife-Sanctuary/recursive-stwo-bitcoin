use crate::bar::{dummy_script, AllocBar, AllocationMode, Bar};
use crate::basic::str::StrBar;
use crate::bitcoin_system::{BitcoinSystemRef, Element};
use crate::options::Options;
use crate::stack::Stack;
use crate::treepp::*;
use anyhow::Result;
use bitcoin::opcodes::all::OP_CAT;
use bitcoin::opcodes::Ordinary::OP_SHA256;
use bitcoin::script::write_scriptint;
use num_traits::Zero;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::ops::Add;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

#[derive(Clone)]
pub struct Sha256HashBar {
    pub variable: usize,
    pub value: Sha256Hash,
    pub cs: BitcoinSystemRef,
}

impl Bar for Sha256HashBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        vec![self.variable]
    }

    fn length() -> usize {
        1
    }
}

impl AllocBar for Sha256HashBar {
    type Value = Sha256Hash;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value.clone())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        Ok(Self {
            variable: cs.alloc(Element::Str(data.as_ref().to_vec()), mode)?,
            value: data,
            cs: cs.clone(),
        })
    }
}

impl Add for &Sha256HashBar {
    type Output = Sha256HashBar;

    fn add(self, rhs: Self) -> Sha256HashBar {
        let cs = self.cs.and(&rhs.cs());

        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, rhs.value.as_ref());
        Update::update(&mut sha256, self.value.as_ref());
        let hash = sha256.finalize().to_vec();

        cs.insert_script(hash_combine, [rhs.variable, self.variable])
            .unwrap();
        Sha256HashBar::new_function_output(&cs, hash.into()).unwrap()
    }
}

impl<T: Bar + AllocBar> From<&T> for Sha256HashBar {
    fn from(v: &T) -> Sha256HashBar {
        let variables = v.variables();
        let cs = v.cs();

        let mut cur_hash = Option::<Vec<u8>>::None;
        for &variable in variables.iter().rev() {
            let mut sha256 = Sha256::new();
            match cs.get_element(variable).unwrap() {
                Element::Num(v) => {
                    Update::update(&mut sha256, &bitcoin_num_to_bytes(v as i64));
                }
                Element::Str(v) => {
                    Update::update(&mut sha256, &v);
                }
            }
            if let Some(cur_hash) = cur_hash {
                Update::update(&mut sha256, &cur_hash);
            }
            cur_hash = Some(sha256.finalize().to_vec());
        }

        let len = variables.len() as u32;
        let options = Options::new().with_u32("len", len);
        cs.insert_script_complex(hash_many, variables, &options)
            .unwrap();

        Sha256HashBar::new_function_output(&cs, cur_hash.unwrap().into()).unwrap()
    }
}

impl<T: Bar> From<&[T]> for Sha256HashBar {
    fn from(values: &[T]) -> Self {
        assert!(!values.len().is_zero());

        let mut cs = values[0].cs();
        for value in values.iter().skip(1) {
            cs = cs.and(&value.cs());
        }

        let mut variables = vec![];
        for value in values.iter() {
            variables.extend(value.variables());
        }

        let mut cur_hash = Option::<Vec<u8>>::None;
        for &variable in variables.iter().rev() {
            let mut sha256 = Sha256::new();
            match cs.get_element(variable).unwrap() {
                Element::Num(v) => {
                    Update::update(&mut sha256, &bitcoin_num_to_bytes(v as i64));
                }
                Element::Str(v) => {
                    Update::update(&mut sha256, &v);
                }
            }
            if let Some(cur_hash) = cur_hash {
                Update::update(&mut sha256, &cur_hash);
            }
            cur_hash = Some(sha256.finalize().to_vec());
        }

        let len = variables.len() as u32;
        let options = Options::new().with_u32("len", len);
        cs.insert_script_complex(hash_many, variables, &options)
            .unwrap();

        Sha256HashBar::new_function_output(&cs, cur_hash.unwrap().into()).unwrap()
    }
}

impl From<&Sha256HashBar> for StrBar {
    fn from(v: &Sha256HashBar) -> StrBar {
        let cs = v.cs();
        cs.insert_script(dummy_script, v.variables()).unwrap();
        StrBar::new_function_output(&cs, v.value().unwrap().into()).unwrap()
    }
}

fn hash_many(_: &mut Stack, options: &Options) -> Result<Script> {
    let len = options.get_u32("len")?;
    Ok(script! {
        OP_SHA256
        for _ in 0..len - 1 {
            OP_CAT OP_SHA256
        }
    })
}

fn hash_combine() -> Script {
    Script::from(vec![OP_CAT.to_u8(), OP_SHA256.to_u8()])
}

pub fn bitcoin_num_to_bytes(v: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let l = write_scriptint(&mut buf, v);
    buf[0..l].to_vec()
}
