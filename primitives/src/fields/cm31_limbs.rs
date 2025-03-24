use crate::fields::cm31::CM31Bar;
use crate::fields::m31_limbs::M31LimbsBar;
use crate::fields::table::m31::{M31Limbs, M31LimbsGadget};
use crate::fields::table::TableBar;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use std::ops::{Add, Mul};

#[derive(Clone)]
pub struct CM31LimbsBar {
    pub real: M31LimbsBar,
    pub imag: M31LimbsBar,
}

impl Bar for CM31LimbsBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.real.cs.and(&self.imag.cs)
    }

    fn variables(&self) -> Vec<usize> {
        let mut variables = self.real.variables();
        variables.extend(self.imag.variables());
        variables
    }

    fn length() -> usize {
        8
    }
}

impl From<&CM31Bar> for CM31LimbsBar {
    fn from(var: &CM31Bar) -> Self {
        let real = M31LimbsBar::from(&var.real);
        let imag = M31LimbsBar::from(&var.imag);

        Self { real, imag }
    }
}

impl Mul<(&TableBar, &CM31LimbsBar)> for &CM31LimbsBar {
    type Output = CM31Bar;

    fn mul(self, rhs: (&TableBar, &CM31LimbsBar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_sum = &self.real + &self.imag;
        let rhs_sum = &rhs.real + &rhs.imag;

        let sum_product = &self_sum * (table, &rhs_sum);
        let real_product = &self.real * (table, &rhs.real);
        let imag_product = &self.imag * (table, &rhs.imag);

        let new_real = &real_product - &imag_product;
        let new_imag = &(&sum_product - &real_product) - &imag_product;

        CM31Bar {
            real: new_real,
            imag: new_imag,
        }
    }
}

impl Add<&CM31LimbsBar> for &CM31LimbsBar {
    type Output = CM31LimbsBar;

    fn add(self, rhs: &CM31LimbsBar) -> Self::Output {
        let new_real_limbs = M31Limbs::add_limbs_with_reduction(&self.real.value, &rhs.real.value);
        let new_imag_limbs = M31Limbs::add_limbs_with_reduction(&self.imag.value, &rhs.imag.value);

        let cs = self.cs().and(&rhs.cs());
        cs.insert_script(
            M31LimbsGadget::add_limbs_with_reduction,
            self.real
                .variables()
                .iter()
                .chain(rhs.real.variables.iter())
                .copied(),
        )
        .unwrap();
        let real = M31LimbsBar::new_function_output(
            &cs,
            [
                new_real_limbs[0],
                new_real_limbs[1],
                new_real_limbs[2],
                new_real_limbs[3],
            ],
        )
        .unwrap();

        cs.insert_script(
            M31LimbsGadget::add_limbs_with_reduction,
            self.imag
                .variables()
                .iter()
                .chain(rhs.imag.variables.iter())
                .copied(),
        )
        .unwrap();
        let imag = M31LimbsBar::new_function_output(
            &cs,
            [
                new_imag_limbs[0],
                new_imag_limbs[1],
                new_imag_limbs[2],
                new_imag_limbs[3],
            ],
        )
        .unwrap();

        CM31LimbsBar { real, imag }
    }
}

#[cfg(test)]
mod test {
    use crate::fields::cm31::CM31Bar;
    use crate::fields::cm31_limbs::CM31LimbsBar;
    use crate::fields::table::TableBar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_cm31, test_program};

    #[test]
    fn test_cm31_limbs_table_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_cm31(&mut prng);
        let b_val = rand_cm31(&mut prng);
        let expected = a_val * b_val;

        let cs = BitcoinSystemRef::new_ref();

        let a = CM31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = CM31LimbsBar::from(&a);

        let b = CM31Bar::new_constant(&cs, b_val).unwrap();
        let b_limbs = CM31LimbsBar::from(&b);

        let table = TableBar::new_constant(&cs, ()).unwrap();
        let res = &a_limbs * (&table, &b_limbs);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                { expected.1 }
                { expected.0 }
            },
        )
        .unwrap();
    }
}
