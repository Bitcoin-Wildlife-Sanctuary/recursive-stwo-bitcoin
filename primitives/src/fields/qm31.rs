use crate::fields::cm31::CM31Bar;
use crate::fields::cm31_limbs::CM31LimbsBar;
use crate::fields::m31::M31Bar;
use crate::fields::m31_limbs::M31LimbsBar;
use crate::fields::qm31_limbs::QM31LimbsBar;
use crate::fields::table::TableBar;
use anyhow::Result;
use num_traits::{One, Zero};
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar, CopyBar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::treepp::*;
use rust_bitcoin_m31::{m31_add_n31, m31_sub, push_m31_one, push_n31_one, qm31_swap};
use std::ops::{Add, Mul, Neg, Sub};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

#[derive(Clone)]
pub struct QM31Bar {
    pub first: CM31Bar,
    pub second: CM31Bar,
}

impl Add<&QM31Bar> for &Sha256HashBar {
    type Output = Sha256HashBar;

    fn add(self, rhs: &QM31Bar) -> Sha256HashBar {
        let felt_hash = Sha256HashBar::from(rhs);
        self + &felt_hash
    }
}

impl Bar for QM31Bar {
    fn cs(&self) -> BitcoinSystemRef {
        self.first.cs().and(&self.second.cs())
    }

    fn variables(&self) -> Vec<usize> {
        vec![
            self.second.imag.variable,
            self.second.real.variable,
            self.first.imag.variable,
            self.first.real.variable,
        ]
    }

    fn length() -> usize {
        4
    }
}

impl AllocBar for QM31Bar {
    type Value = QM31;

    fn value(&self) -> Result<Self::Value> {
        Ok(QM31(self.first.value()?, self.second.value()?))
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let second = CM31Bar::new_variable(cs, data.1, mode)?;
        let first = CM31Bar::new_variable(cs, data.0, mode)?;

        Ok(Self { first, second })
    }
}

impl Add for &QM31Bar {
    type Output = QM31Bar;

    fn add(self, rhs: Self) -> Self::Output {
        let second = &self.second + &rhs.second;
        let first = &self.first + &rhs.first;

        QM31Bar { first, second }
    }
}

impl Add<&CM31Bar> for &QM31Bar {
    type Output = QM31Bar;

    fn add(self, rhs: &CM31Bar) -> Self::Output {
        let second = self.second.copy().unwrap();
        let first = &self.first + rhs;

        QM31Bar { first, second }
    }
}

impl Add<&M31Bar> for &QM31Bar {
    type Output = QM31Bar;

    fn add(self, rhs: &M31Bar) -> Self::Output {
        let second = self.second.copy().unwrap();
        let first = &self.first + rhs;

        QM31Bar { first, second }
    }
}

impl Add<&M31Bar> for QM31Bar {
    type Output = QM31Bar;

    fn add(self, rhs: &M31Bar) -> Self::Output {
        let second = self.second.copy().unwrap();
        let first = &self.first + rhs;

        QM31Bar { first, second }
    }
}

impl Sub for &QM31Bar {
    type Output = QM31Bar;

    fn sub(self, rhs: Self) -> Self::Output {
        let second = &self.second - &rhs.second;
        let first = &self.first - &rhs.first;

        QM31Bar { first, second }
    }
}

impl Sub<&CM31Bar> for &QM31Bar {
    type Output = QM31Bar;

    fn sub(self, rhs: &CM31Bar) -> Self::Output {
        let second = self.second.copy().unwrap();
        let first = &self.first - rhs;

        QM31Bar { first, second }
    }
}

impl Sub<&M31Bar> for QM31Bar {
    type Output = QM31Bar;

    fn sub(self, rhs: &M31Bar) -> Self::Output {
        let second = self.second.copy().unwrap();
        let first = &self.first - rhs;

        QM31Bar { first, second }
    }
}

impl Mul<(&TableBar, &QM31Bar)> for &QM31Bar {
    type Output = QM31Bar;

    fn mul(self, rhs: (&TableBar, &QM31Bar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_limbs = QM31LimbsBar::from(self);
        let rhs_limbs = QM31LimbsBar::from(rhs);
        &self_limbs * (table, &rhs_limbs)
    }
}

impl Mul<(&TableBar, &M31Bar)> for &QM31Bar {
    type Output = QM31Bar;

    fn mul(self, rhs: (&TableBar, &M31Bar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_limbs = QM31LimbsBar::from(self);
        let rhs_limbs = M31LimbsBar::from(rhs);

        let res_first_real = &self_limbs.first.real * (table, &rhs_limbs);
        let res_first_imag = &self_limbs.first.imag * (table, &rhs_limbs);
        let res_second_real = &self_limbs.second.real * (table, &rhs_limbs);
        let res_second_imag = &self_limbs.second.imag * (table, &rhs_limbs);

        QM31Bar {
            first: CM31Bar {
                imag: res_first_imag,
                real: res_first_real,
            },
            second: CM31Bar {
                imag: res_second_imag,
                real: res_second_real,
            },
        }
    }
}

impl Mul<(&TableBar, &CM31Bar)> for &QM31Bar {
    type Output = QM31Bar;

    fn mul(self, rhs: (&TableBar, &CM31Bar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_limbs = QM31LimbsBar::from(self);
        let rhs_limbs = CM31LimbsBar::from(rhs);

        let res_first = &self_limbs.first * (table, &rhs_limbs);
        let res_second = &self_limbs.second * (table, &rhs_limbs);

        QM31Bar {
            first: res_first,
            second: res_second,
        }
    }
}

impl Mul for &QM31Bar {
    type Output = QM31Bar;

    fn mul(self, rhs: Self) -> Self::Output {
        println!("Warning: multiplication without using a table");
        let res = self.value().unwrap() * rhs.value().unwrap();
        let cs = self.cs().and(&rhs.cs());

        cs.insert_script(
            rust_bitcoin_m31::qm31_mul,
            self.variables()
                .iter()
                .chain(rhs.variables().iter())
                .copied(),
        )
        .unwrap();

        QM31Bar::new_function_output(&cs, res).unwrap()
    }
}

impl Neg for &QM31Bar {
    type Output = QM31Bar;

    fn neg(self) -> Self::Output {
        let first = -(&self.first);
        let second = -(&self.second);

        QM31Bar { first, second }
    }
}

impl QM31Bar {
    pub fn is_zero(&self) {
        assert_eq!(self.value().unwrap(), QM31::zero());
        self.first.is_zero();
        self.second.is_zero();
    }

    pub fn is_one(&self) {
        assert_eq!(self.value().unwrap(), QM31::from_u32_unchecked(1, 0, 0, 0));
        self.first.is_one();
        self.second.is_zero();
    }

    pub fn from_m31(a: &M31Bar, b: &M31Bar, c: &M31Bar, d: &M31Bar) -> QM31Bar {
        QM31Bar {
            first: CM31Bar::from_m31(a, b),
            second: CM31Bar::from_m31(c, d),
        }
    }

    pub fn to_m31_array(&self) -> [M31Bar; 4] {
        [
            self.first.real.clone(),
            self.first.imag.clone(),
            self.second.real.clone(),
            self.second.imag.clone(),
        ]
    }

    pub fn add1(&self) -> QM31Bar {
        let mut res = self.value().unwrap();
        res.0 .0 += M31::one();
        let cs = self.cs();

        cs.insert_script(qm31_1add_gadget, self.variables())
            .unwrap();

        QM31Bar::new_function_output(&cs, res).unwrap()
    }

    pub fn sub1(&self) -> QM31Bar {
        let mut res = self.value().unwrap();
        res.0 .0 -= M31::one();
        let cs = self.cs();

        cs.insert_script(qm31_1sub_gadget, self.variables())
            .unwrap();

        QM31Bar::new_function_output(&cs, res).unwrap()
    }

    pub fn shift_by_i(&self) -> QM31Bar {
        let first = self.first.shift_by_i();
        let second = self.second.shift_by_i();

        QM31Bar { first, second }
    }

    pub fn shift_by_j(&self) -> QM31Bar {
        let second = self.first.copy().unwrap();

        let mut first = &self.second + &self.second;
        first.real = &first.real - &self.second.imag;
        first.imag = &first.imag + &self.second.real;

        QM31Bar { first, second }
    }

    pub fn shift_by_ij(&self) -> QM31Bar {
        self.shift_by_i().shift_by_j()
    }

    pub fn inverse(&self, table: &TableBar) -> QM31Bar {
        let cs = self.cs();
        let res = self.value().unwrap().inverse();

        let res_var = QM31Bar::new_hint(&cs, res).unwrap();
        let expected_one = &res_var * (table, self);
        expected_one.is_one();

        res_var
    }

    pub fn inverse_without_table(&self) -> QM31Bar {
        let cs = self.cs();
        let res = self.value().unwrap().inverse();

        let res_var = QM31Bar::new_hint(&cs, res).unwrap();
        let expected_one = &res_var * self;
        expected_one.is_one();

        res_var
    }

    pub fn conditional_swap(&self, rhs: &QM31Bar, bit: &M31Bar) -> (QM31Bar, QM31Bar) {
        assert!(bit.value.0 == 0 || bit.value.0 == 1);

        let res = if bit.value.0 == 0 {
            (self.value().unwrap(), rhs.value().unwrap())
        } else {
            (rhs.value().unwrap(), self.value().unwrap())
        };

        let cs = self.cs().and(&rhs.cs()).and(&bit.cs());

        cs.insert_script(
            qm31_conditional_swap_gadget,
            self.variables()
                .iter()
                .chain(rhs.variables().iter())
                .chain(bit.variables().iter())
                .copied(),
        )
        .unwrap();

        let res_1_var = QM31Bar::new_function_output(&cs, res.0).unwrap();
        let res_2_var = QM31Bar::new_function_output(&cs, res.1).unwrap();

        (res_1_var, res_2_var)
    }
}

fn qm31_1add_gadget() -> Script {
    script! {
        push_n31_one
        m31_add_n31
    }
}

fn qm31_1sub_gadget() -> Script {
    script! {
        push_m31_one
        m31_sub
    }
}

fn qm31_conditional_swap_gadget() -> Script {
    script! {
        OP_IF
            qm31_swap
        OP_ENDIF
    }
}

#[cfg(test)]
mod test {
    use crate::fields::qm31::QM31Bar;
    use crate::fields::table::TableBar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_qm31, test_program};

    #[test]
    fn qm31_inverse() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_qm31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = QM31Bar::new_constant(&cs, a_val).unwrap();
        let table = TableBar::new_constant(&cs, ()).unwrap();

        let a_inv = a.inverse(&table);
        let res = &a * (&table, &a_inv);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                0
                0
                0
                1
            },
        )
        .unwrap();
    }

    #[test]
    fn qm31_inverse_without_table() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_qm31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = QM31Bar::new_constant(&cs, a_val).unwrap();

        let a_inv = a.inverse_without_table();
        let res = &a * &a_inv;

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                0
                0
                0
                1
            },
        )
        .unwrap();
    }
}
