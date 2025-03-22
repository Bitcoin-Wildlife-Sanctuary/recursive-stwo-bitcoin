use crate::bar::{AllocBar, AllocationMode, Bar};
use crate::bitcoin_system::{BitcoinSystemRef, Element};
use crate::treepp::*;
use anyhow::Result;
use std::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Debug, Clone)]
pub struct BoolBar {
    pub variable: usize,
    pub value: bool,
    pub cs: BitcoinSystemRef,
}

impl Bar for BoolBar {
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

impl AllocBar for BoolBar {
    type Value = bool;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value)
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let num = if data { 1 } else { 0 };
        Ok(Self {
            variable: cs.alloc(Element::Num(num), mode)?,
            value: data,
            cs: cs.clone(),
        })
    }
}

impl Not for &BoolBar {
    type Output = BoolBar;

    fn not(self) -> Self::Output {
        self.cs
            .insert_script(bool_var_not, self.variables())
            .unwrap();
        BoolBar::new_function_output(&self.cs, !self.value).unwrap()
    }
}

fn bool_var_not() -> Script {
    script! {
        OP_NOT
    }
}

impl BitAnd<&BoolBar> for &BoolBar {
    type Output = BoolBar;

    fn bitand(self, rhs: &BoolBar) -> Self::Output {
        self.cs
            .insert_script(bool_var_and, vec![self.variable, rhs.variable])
            .unwrap();
        BoolBar::new_function_output(&self.cs, self.value & rhs.value).unwrap()
    }
}

fn bool_var_and() -> Script {
    script! {
        OP_AND
    }
}

impl BitOr<&BoolBar> for &BoolBar {
    type Output = BoolBar;

    fn bitor(self, rhs: &BoolBar) -> Self::Output {
        self.cs
            .insert_script(bool_var_or, vec![self.variable, rhs.variable])
            .unwrap();
        BoolBar::new_function_output(&self.cs, self.value | rhs.value).unwrap()
    }
}

fn bool_var_or() -> Script {
    script! {
        OP_OR
    }
}

impl BitXor<&BoolBar> for &BoolBar {
    type Output = BoolBar;

    fn bitxor(self, rhs: &BoolBar) -> Self::Output {
        self.cs
            .insert_script(bool_var_xor, vec![self.variable, rhs.variable])
            .unwrap();
        BoolBar::new_function_output(&self.cs, self.value ^ rhs.value).unwrap()
    }
}

fn bool_var_xor() -> Script {
    script! {
        // x 0 -> x
        // x 1 -> !x
        OP_IF OP_NOT OP_ENDIF
    }
}

impl BoolBar {
    pub fn verify(self) {
        assert!(self.value);
        self.cs
            .insert_script(bool_var_verify, vec![self.variable])
            .unwrap()
    }
}

fn bool_var_verify() -> Script {
    script! {
        OP_VERIFY
    }
}
