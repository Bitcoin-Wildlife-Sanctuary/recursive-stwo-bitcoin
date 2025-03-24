use crate::bar::{AllocBar, AllocationMode, Bar};
use crate::bitcoin_system::{BitcoinSystemRef, Element};
use crate::treepp::*;
use anyhow::Result;
use std::ops::{Add, Sub};

#[derive(Debug, Clone)]
pub struct U8Bar {
    pub variable: usize,
    pub value: u8,
    pub cs: BitcoinSystemRef,
}

impl Bar for U8Bar {
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

impl AllocBar for U8Bar {
    type Value = u8;

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value)
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        Ok(Self {
            variable: cs.alloc(Element::Num(data as i32), mode)?,
            value: data,
            cs: cs.clone(),
        })
    }
}

impl Add for &U8Bar {
    type Output = U8Bar;

    fn add(self, rhs: Self) -> Self::Output {
        let res = self.value.checked_add(rhs.value).unwrap();

        let cs = self.cs.and(&rhs.cs);

        cs.insert_script(u8_add, [self.variable, rhs.variable])
            .unwrap();

        let res_var = U8Bar::new_variable(&cs, res, AllocationMode::FunctionOutput).unwrap();
        res_var
    }
}

fn u8_add() -> Script {
    script! {
        OP_ADD
    }
}

impl Sub for &U8Bar {
    type Output = U8Bar;

    fn sub(self, rhs: Self) -> Self::Output {
        let res = self.value.checked_sub(rhs.value).unwrap();

        let cs = self.cs.and(&rhs.cs);

        cs.insert_script(u8_sub, [self.variable, rhs.variable])
            .unwrap();

        let res_var = U8Bar::new_variable(&cs, res, AllocationMode::FunctionOutput).unwrap();
        res_var
    }
}

fn u8_sub() -> Script {
    script! {
        OP_SUB
    }
}

impl U8Bar {
    pub fn check_format(&self) -> Result<()> {
        self.cs.insert_script(u8_check_format, [self.variable])
    }
}

fn u8_check_format() -> Script {
    script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        255 OP_LESSTHANOREQUAL OP_VERIFY
    }
}

#[cfg(test)]
mod test {
    use crate::bar::{AllocBar, AllocationMode};
    use crate::basic::u8::U8Bar;
    use crate::bitcoin_system::{BitcoinSystemRef, Element};
    use crate::test_program;
    use crate::treepp::*;

    #[test]
    fn test_add_u8() {
        let cs = BitcoinSystemRef::new_ref();

        let a = U8Bar::new_constant(&cs, 8).unwrap();
        let b = U8Bar::new_constant(&cs, 4).unwrap();

        let c = &a + &b;
        c.check_format().unwrap();
        cs.set_program_output(&c).unwrap();
        test_program(cs, script! { 12 }).unwrap();
    }

    #[test]
    fn test_sub_u8() {
        let cs = BitcoinSystemRef::new_ref();
        let a = U8Bar::new_constant(&cs, 8).unwrap();
        let b = U8Bar::new_constant(&cs, 3).unwrap();

        let c = &a - &b;
        c.check_format().unwrap();
        cs.set_program_output(&c).unwrap();
        test_program(cs, script! { 5 }).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_add_u8_overflow() {
        let cs = BitcoinSystemRef::new_ref();

        let a = U8Bar::new_constant(&cs, 8).unwrap();
        let b = U8Bar::new_constant(&cs, 248).unwrap();

        let _ = &a + &b;
    }

    #[test]
    #[should_panic]
    fn test_sub_u8_overflow() {
        let cs = BitcoinSystemRef::new_ref();

        let a = U8Bar::new_constant(&cs, 8).unwrap();
        let b = U8Bar::new_constant(&cs, 9).unwrap();

        let _ = &a - &b;
    }

    #[test]
    fn test_check_format() {
        let cs = BitcoinSystemRef::new_ref();

        let a = U8Bar::new_constant(&cs, 8).unwrap();
        a.check_format().unwrap();
        test_program(cs, script! {}).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_check_format_overflow() {
        let cs = BitcoinSystemRef::new_ref();

        let mut a = U8Bar::new_constant(&cs, 8).unwrap();
        a.variable = cs
            .alloc(Element::Num(-1), AllocationMode::Constant)
            .unwrap();
        a.check_format().unwrap();
        test_program(cs, script! {}).unwrap();
    }
}
