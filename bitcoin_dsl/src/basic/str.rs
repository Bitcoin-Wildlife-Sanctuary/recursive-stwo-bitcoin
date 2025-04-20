use crate::bar::{AllocBar, AllocationMode, Bar};
use crate::basic::bool::BoolBar;
use crate::bitcoin_system::{BitcoinSystemRef, Element};
use crate::options::Options;
use crate::stack::Stack;
use crate::treepp::*;
use anyhow::Result;
use bitcoin::opcodes::all::OP_CAT;
use sha2::{Digest, Sha256};
use std::ops::Add;

#[derive(Clone, Debug)]
pub struct StrBar {
    pub variable: usize,
    pub value: Vec<u8>,
    pub cs: BitcoinSystemRef,
}

impl Bar for StrBar {
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

impl AllocBar for StrBar {
    type Value = Vec<u8>;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value.clone())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        Ok(Self {
            variable: cs.alloc(Element::Str(data.clone()), mode)?,
            value: data,
            cs: cs.clone(),
        })
    }
}

impl Add for &StrBar {
    type Output = StrBar;

    fn add(self, rhs: Self) -> Self::Output {
        let cs = self.cs().and(&rhs.cs());

        let mut res = self.value.clone();
        res.extend_from_slice(&rhs.value);

        cs.insert_script(str_concatenate_gadget, vec![self.variable, rhs.variable])
            .unwrap();

        StrBar::new_function_output(&cs, res).unwrap()
    }
}

impl StrBar {
    pub fn len_equalverify(&self, l: usize) {
        assert_eq!(self.value.len(), l);

        let cs = self.cs();
        cs.insert_script_complex(
            len_equalverify_gadget,
            self.variables(),
            &Options::new().with_u32("len", l as u32),
        )
        .unwrap();
    }

    pub fn len_lessthan(&self, l: usize) {
        assert!(self.value.len() < l);

        let cs = self.cs();
        cs.insert_script_complex(
            len_lessthan_gadget,
            self.variables(),
            &Options::new().with_u32("len", l as u32),
        )
        .unwrap();
    }

    pub fn len_lessthanorequal(&self, l: usize) {
        assert!(self.value.len() < l + 1);

        let cs = self.cs();
        cs.insert_script_complex(
            len_lessthan_gadget,
            self.variables(),
            &Options::new().with_u32("len", (l + 1) as u32),
        )
        .unwrap();
    }

    pub fn hash(&self) -> Result<StrBar> {
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, &self.value);
        let hash_value = sha256.finalize().to_vec();

        let cs = self.cs();
        cs.insert_script(str_hash_gadget, self.variables())?;
        StrBar::new_function_output(&cs, hash_value)
    }

    pub fn swap(lhs: &StrBar, rhs: &StrBar, bit: &BoolBar) -> Result<(StrBar, StrBar)> {
        let lhs_value = lhs.value()?;
        let rhs_value = rhs.value()?;

        let cs = lhs.cs().and(&rhs.cs());
        cs.insert_script(
            str_swap_gadget,
            vec![lhs.variable, rhs.variable, bit.variable],
        )?;
        if !bit.value {
            Ok((
                StrBar::new_function_output(&cs, lhs_value)?,
                StrBar::new_function_output(&cs, rhs_value)?,
            ))
        } else {
            Ok((
                StrBar::new_function_output(&cs, rhs_value)?,
                StrBar::new_function_output(&cs, lhs_value)?,
            ))
        }
    }
}

fn str_hash_gadget() -> Script {
    script! { OP_SHA256 }
}

fn str_swap_gadget() -> Script {
    script! {
        OP_IF OP_SWAP OP_ENDIF
    }
}

fn str_concatenate_gadget() -> Script {
    Script::from(vec![OP_CAT.to_u8()])
}

fn len_equalverify_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let len = options.get_u32("len")?;
    Ok(script! {
        OP_SIZE { len } OP_EQUALVERIFY OP_DROP
    })
}

fn len_lessthan_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let len = options.get_u32("len")?;
    Ok(script! {
        OP_SIZE { len } OP_LESSTHAN OP_VERIFY OP_DROP
    })
}
