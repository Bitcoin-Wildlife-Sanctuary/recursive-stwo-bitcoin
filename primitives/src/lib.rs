pub mod channel;

pub mod fields;

pub mod circle;

pub mod bits;

pub mod pow;

pub mod utils;

pub mod input_sum;

pub mod composition;

pub mod quotient;

#[cfg(test)]
mod test {
    use crate::fields::m31::M31Bar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_m31, test_program};

    #[test]
    fn test_m31_mult() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut a_val = rand_m31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let mut a = M31Bar::new_program_input(&cs, a_val).unwrap();

        for _ in 0..10 {
            let b_val = rand_m31(&mut prng);

            let b = M31Bar::new_constant(&cs, b_val).unwrap();

            let c = &a * &b;
            let c_val = a_val * b_val;
            assert_eq!(c.value, c_val);

            a = c;
            a_val = c_val;
        }

        cs.set_program_output(&a).unwrap();

        test_program(
            cs,
            script! {
                { a_val.0 }
            },
        )
        .unwrap();
    }
}
