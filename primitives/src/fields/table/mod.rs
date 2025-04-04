use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::{BitcoinSystemRef, Element};
use recursive_stwo_bitcoin_dsl::treepp::pushable::*;
use std::ops::Index;
use std::sync::OnceLock;

pub mod lookup;
pub mod m31;
pub mod utils;

pub static TABLE: OnceLock<Table> = OnceLock::new();

#[derive(Clone)]
pub struct Table {
    pub data: Vec<i64>,
}

impl Index<usize> for Table {
    type Output = i64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Pushable for &Table {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for &i in self.data.iter().rev() {
            builder = builder.push_int(i);
        }
        builder
    }
}

pub fn generate_table<const N: usize>() -> Table {
    assert!(N >= 1);
    assert!(N <= 9);

    let mut v = vec![0i64; (1 << N) + 1];

    for (i, v) in v.iter_mut().enumerate().take((1 << N) + 1) {
        *v = ((i * i) / 4) as i64;
    }

    Table { data: v }
}

pub fn get_table() -> &'static Table {
    TABLE.get_or_init(generate_table::<9>)
}

#[derive(Clone)]
pub struct TableBar {
    pub variables: Vec<usize>,
    pub cs: BitcoinSystemRef,
}

impl Bar for TableBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.clone()
    }

    fn length() -> usize {
        513
    }
}

impl AllocBar for TableBar {
    type Value = ();

    fn value(&self) -> Result<Self::Value> {
        Ok(())
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        assert_eq!(mode, AllocationMode::Constant);
        Self::new_constant(cs, data)
    }

    fn new_constant(cs: &BitcoinSystemRef, _: Self::Value) -> Result<Self> {
        let table = get_table();

        let mut variables = vec![];
        for &elem in table.data.iter().rev() {
            variables.push(cs.alloc(Element::Num(elem as i32), AllocationMode::Constant)?);
        }

        Ok(Self {
            variables,
            cs: cs.clone(),
        })
    }

    fn new_program_input(_: &BitcoinSystemRef, _: Self::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_function_output(_: &BitcoinSystemRef, _: Self::Value) -> Result<Self> {
        unimplemented!()
    }

    fn new_hint(_: &BitcoinSystemRef, _: Self::Value) -> Result<Self> {
        unimplemented!()
    }
}
