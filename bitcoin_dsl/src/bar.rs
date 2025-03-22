use crate::bitcoin_system::BitcoinSystemRef;
use crate::treepp::*;
use anyhow::Result;
use bitcoin::opcodes::Ordinary::OP_EQUALVERIFY;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// This trait describes some core functionality that is common to high-level variables.
pub trait Bar: Clone {
    /// Returns the underlying `BitcoinSystemRef`.
    fn cs(&self) -> BitcoinSystemRef;

    /// Returns the assigned stack elements indices.
    fn variables(&self) -> Vec<usize>;

    /// Returns the length (in terms of number of elements in the stack) of the value.
    fn length() -> usize;

    fn equalverify(&self, rhs: &Self) -> Result<()> {
        let cs = self.cs().and(&rhs.cs());

        for (&self_var, &rhs_var) in self.variables().iter().zip(rhs.variables().iter()) {
            cs.insert_script(
                single_elem_equalverify as fn() -> Script,
                [self_var, rhs_var],
            )?;
        }

        Ok(())
    }
}

pub trait AllocBar: Sized {
    /// The type of the "native" value that `Self` represents in the bitcoin
    /// system.
    type Value: Clone + Serialize + DeserializeOwned;

    /// Returns the value that is assigned to `self` in the underlying
    /// `ConstraintSystem`.
    fn value(&self) -> Result<Self::Value>;

    fn new_variable(cs: &BitcoinSystemRef, data: Self::Value, mode: AllocationMode)
        -> Result<Self>;

    fn new_constant(cs: &BitcoinSystemRef, data: Self::Value) -> Result<Self> {
        Self::new_variable(cs, data, AllocationMode::Constant)
    }

    fn new_program_input(cs: &BitcoinSystemRef, data: Self::Value) -> Result<Self> {
        Self::new_variable(cs, data, AllocationMode::ProgramInput)
    }

    fn new_function_output(cs: &BitcoinSystemRef, data: Self::Value) -> Result<Self> {
        Self::new_variable(cs, data, AllocationMode::FunctionOutput)
    }

    fn new_hint(cs: &BitcoinSystemRef, data: Self::Value) -> Result<Self> {
        Self::new_variable(cs, data, AllocationMode::Hint)
    }
}

pub trait CopyBar: Bar + AllocBar {
    fn copy(&self) -> Result<Self> {
        let cs = self.cs();
        cs.insert_script(dummy_script, self.variables())?;
        Self::new_function_output(&cs, self.value()?)
    }
}

impl<T: Bar + AllocBar> CopyBar for T {}

pub(crate) fn dummy_script() -> Script {
    script! {}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocationMode {
    ProgramInput,
    FunctionOutput,
    Constant,
    Hint,
}

fn single_elem_equalverify() -> Script {
    Script::from(vec![OP_EQUALVERIFY.to_u8()])
}
