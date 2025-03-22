use crate::cm31_limbs::CM31LimbsBar;
use crate::qm31::QM31Bar;
use crate::table::TableBar;
use recursive_stwo_bitcoin_dsl::bar::Bar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use std::ops::Mul;

#[derive(Clone)]
pub struct QM31LimbsBar {
    pub first: CM31LimbsBar,
    pub second: CM31LimbsBar,
}

impl Bar for QM31LimbsBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.first.cs().and(&self.second.cs())
    }

    fn variables(&self) -> Vec<usize> {
        let mut variables = self.first.variables();
        variables.extend(self.second.variables());
        variables
    }

    fn length() -> usize {
        16
    }
}

impl From<&QM31Bar> for QM31LimbsBar {
    fn from(var: &QM31Bar) -> Self {
        let first = CM31LimbsBar::from(&var.first);
        let second = CM31LimbsBar::from(&var.second);

        Self { first, second }
    }
}

impl Mul<(&TableBar, &QM31LimbsBar)> for &QM31LimbsBar {
    type Output = QM31Bar;

    fn mul(self, rhs: (&TableBar, &QM31LimbsBar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_sum = &self.first + &self.second;
        let rhs_sum = &rhs.first + &rhs.second;

        let sum_product = &self_sum * (table, &rhs_sum);
        let first_product = &self.first * (table, &rhs.first);
        let second_product = &self.second * (table, &rhs.second);

        let mut first = &first_product + &second_product;
        first = &first + &second_product;
        let second_product_shifted_by_i = second_product.shift_by_i();
        first = &first + &second_product_shifted_by_i;

        let mut second = &sum_product - &first_product;
        second = &second - &second_product;

        QM31Bar { first, second }
    }
}

#[cfg(test)]
mod test {
    use crate::qm31::QM31Bar;
    use crate::qm31_limbs::QM31LimbsBar;
    use crate::table::TableBar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_qm31, test_program};

    #[test]
    fn test_qm31_limbs_table_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_qm31(&mut prng);
        let b_val = rand_qm31(&mut prng);
        let expected = a_val * b_val;

        let cs = BitcoinSystemRef::new_ref();

        let a = QM31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = QM31LimbsBar::from(&a);

        let b = QM31Bar::new_constant(&cs, b_val).unwrap();
        let b_limbs = QM31LimbsBar::from(&b);

        let table = TableBar::new_constant(&cs, ()).unwrap();
        let res = &a_limbs * (&table, &b_limbs);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                { expected.1.1 } { expected.1.0 } { expected.0.1 } { expected.0.0 }
            },
        )
        .unwrap();
    }
}
