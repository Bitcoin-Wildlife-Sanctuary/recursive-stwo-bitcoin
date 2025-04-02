use crate::fields::cm31_limbs::CM31LimbsBar;
use crate::fields::m31::M31Bar;
use crate::fields::m31_limbs::M31LimbsBar;
use crate::fields::table::TableBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar, CopyBar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use std::ops::{Add, Mul, Neg, Sub};
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::FieldExpOps;

#[derive(Clone)]
pub struct CM31Bar {
    pub imag: M31Bar,
    pub real: M31Bar,
}

impl Bar for CM31Bar {
    fn cs(&self) -> BitcoinSystemRef {
        self.real.cs.and(&self.imag.cs)
    }

    fn variables(&self) -> Vec<usize> {
        vec![self.imag.variable, self.real.variable]
    }

    fn length() -> usize {
        2
    }
}

impl AllocBar for CM31Bar {
    type Value = CM31;

    fn value(&self) -> Result<Self::Value> {
        Ok(CM31::from_m31(self.real.value, self.imag.value))
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let imag = M31Bar::new_variable(cs, data.1, mode)?;
        let real = M31Bar::new_variable(cs, data.0, mode)?;

        Ok(Self { imag, real })
    }
}

impl Add for &CM31Bar {
    type Output = CM31Bar;

    fn add(self, rhs: Self) -> Self::Output {
        let imag = &self.imag + &rhs.imag;
        let real = &self.real + &rhs.real;

        CM31Bar { imag, real }
    }
}

impl Add<&M31Bar> for &CM31Bar {
    type Output = CM31Bar;

    fn add(self, rhs: &M31Bar) -> Self::Output {
        let imag = self.imag.copy().unwrap();
        let real = &self.real + rhs;

        CM31Bar { imag, real }
    }
}

impl Sub for &CM31Bar {
    type Output = CM31Bar;

    fn sub(self, rhs: Self) -> Self::Output {
        let imag = &self.imag - &rhs.imag;
        let real = &self.real - &rhs.real;

        CM31Bar { imag, real }
    }
}

impl Sub<&M31Bar> for &CM31Bar {
    type Output = CM31Bar;

    fn sub(self, rhs: &M31Bar) -> Self::Output {
        let imag = self.imag.copy().unwrap();
        let real = &self.real - rhs;

        CM31Bar { imag, real }
    }
}

impl Mul for &CM31Bar {
    type Output = CM31Bar;

    fn mul(self, rhs: Self) -> Self::Output {
        let res = self.value().unwrap() * rhs.value().unwrap();
        let cs = self.cs().and(&rhs.cs());

        cs.insert_script(
            rust_bitcoin_m31::cm31_mul,
            self.variables()
                .iter()
                .chain(rhs.variables().iter())
                .copied(),
        )
        .unwrap();

        CM31Bar::new_function_output(&cs, res).unwrap()
    }
}

impl Mul<(&TableBar, &CM31Bar)> for &CM31Bar {
    type Output = CM31Bar;

    fn mul(self, rhs: (&TableBar, &CM31Bar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_limbs = CM31LimbsBar::from(self);
        let rhs_limbs = CM31LimbsBar::from(rhs);
        &self_limbs * (table, &rhs_limbs)
    }
}

impl Mul<(&TableBar, &M31Bar)> for &CM31Bar {
    type Output = CM31Bar;

    fn mul(self, rhs: (&TableBar, &M31Bar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_limbs = CM31LimbsBar::from(self);
        let rhs_limbs = M31LimbsBar::from(rhs);

        let real = &self_limbs.real * (table, &rhs_limbs);
        let imag = &self_limbs.imag * (table, &rhs_limbs);

        CM31Bar { real, imag }
    }
}

impl Neg for &CM31Bar {
    type Output = CM31Bar;

    fn neg(self) -> Self::Output {
        let real = -&self.real;
        let imag = -&self.imag;

        CM31Bar { imag, real }
    }
}

impl CM31Bar {
    pub fn from_m31(a: &M31Bar, b: &M31Bar) -> CM31Bar {
        CM31Bar {
            imag: b.clone(),
            real: a.clone(),
        }
    }

    pub fn is_one(&self) {
        assert_eq!(self.value().unwrap(), CM31::from_u32_unchecked(1, 0));
        self.real.is_one();
        self.imag.is_zero();
    }

    pub fn is_zero(&self) {
        assert_eq!(self.value().unwrap(), CM31::from_u32_unchecked(0, 0));
        self.real.is_zero();
        self.imag.is_zero();
    }

    pub fn inverse(&self, table: &TableBar) -> Self {
        let cs = self.cs();
        let res = self.value().unwrap().inverse();

        let res_var = CM31Bar::new_hint(&cs, res).unwrap();
        let expected_one = &res_var * (table, self);
        expected_one.is_one();

        res_var
    }

    pub fn inverse_without_table(&self) -> Self {
        let cs = self.cs();
        let res = self.value().unwrap().inverse();

        let res_var = CM31Bar::new_hint(&cs, res).unwrap();
        let expected_one = &res_var * self;
        expected_one.is_one();

        res_var
    }

    pub fn shift_by_i(&self) -> Self {
        let imag = self.real.copy().unwrap();
        let real = -&self.imag;

        Self { imag, real }
    }
}

#[cfg(test)]
mod test {
    use crate::fields::cm31::CM31Bar;
    use crate::fields::table::TableBar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_cm31, test_program};

    #[test]
    fn cm31_inverse() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_cm31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = CM31Bar::new_constant(&cs, a_val).unwrap();
        let table = TableBar::new_constant(&cs, ()).unwrap();

        let a_inv = a.inverse(&table);
        let res = &a * (&table, &a_inv);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                0
                1
            },
        )
        .unwrap();
    }

    #[test]
    fn cm31_inverse_without_table() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_cm31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = CM31Bar::new_constant(&cs, a_val).unwrap();

        let a_inv = a.inverse_without_table();
        let res = &a * &a_inv;

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                0
                1
            },
        )
        .unwrap();
    }
}
