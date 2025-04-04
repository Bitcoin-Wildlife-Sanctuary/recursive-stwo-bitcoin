use crate::fields::m31::M31Bar;
use crate::fields::table::m31::{M31Limbs, M31LimbsGadget, M31Mult, M31MultGadget};
use crate::fields::table::utils::{
    check_limb_format, convert_m31_from_limbs, convert_m31_to_limbs, OP_256MUL,
};
use crate::fields::table::TableBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::{BitcoinSystemRef, Element};
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use std::ops::{Add, Mul};
use stwo_prover::core::fields::m31::M31;

#[derive(Clone)]
pub struct M31LimbsBar {
    pub variables: [usize; 4],
    pub value: [u32; 4],
    pub cs: BitcoinSystemRef,
}

impl Bar for M31LimbsBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.cs.clone()
    }

    fn variables(&self) -> Vec<usize> {
        self.variables.to_vec()
    }

    fn length() -> usize {
        4
    }
}

impl AllocBar for M31LimbsBar {
    type Value = [u32; 4];

    fn value(&self) -> Result<Self::Value> {
        Ok(self.value)
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let mut variables = [0usize; 4];
        for (v, &elem) in variables.iter_mut().zip(data.iter()) {
            *v = cs.alloc(Element::Num(elem as i32), mode)?;
        }
        Ok(Self {
            variables,
            value: data,
            cs: cs.clone(),
        })
    }
}

impl From<&M31Bar> for M31LimbsBar {
    fn from(v: &M31Bar) -> Self {
        let cs = v.cs();
        let num = v.value().unwrap().0;

        let limbs = [
            num & 0xff,
            (num >> 8) & 0xff,
            (num >> 16) & 0xff,
            (num >> 24) & 0xff,
        ];

        let res = M31LimbsBar::new_hint(&cs, limbs).unwrap();
        cs.insert_script(
            m31_to_limbs_gadget,
            v.variables().iter().chain(res.variables().iter()).copied(),
        )
        .unwrap();
        res
    }
}

impl Mul<(&TableBar, &M31LimbsBar)> for &M31LimbsBar {
    type Output = M31Bar;

    fn mul(self, rhs: (&TableBar, &M31LimbsBar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let cs = self.cs().and(&table.cs()).and(&rhs.cs());

        let res = convert_m31_from_limbs(&self.value) * convert_m31_from_limbs(&rhs.value);

        let c_limbs = M31Mult::compute_c_limbs_from_limbs(&self.value, &rhs.value).unwrap();

        let q = M31Mult::compute_q(&c_limbs).unwrap();
        let q_var = M31Bar::new_hint(&cs, M31::from(q)).unwrap();

        let options = Options::new().with_u32("table_ref", table.variables[0] as u32);
        cs.insert_script_complex(
            m31_limbs_mul_gadget,
            self.variables()
                .iter()
                .chain(rhs.variables().iter())
                .chain(q_var.variables().iter())
                .copied(),
            &options,
        )
        .unwrap();

        M31Bar::new_function_output(&cs, res).unwrap()
    }
}

impl M31LimbsBar {
    pub fn inverse(&self, table: &TableBar) -> M31LimbsBar {
        let cs = self.cs();

        let inv = convert_m31_from_limbs(&self.value).inverse();
        let inv_limbs = convert_m31_to_limbs(inv);

        let inv_limbs_var = M31LimbsBar::new_hint(&cs, inv_limbs).unwrap();

        let expected_one = self * (table, &inv_limbs_var);
        expected_one.is_one();

        inv_limbs_var
    }
}

impl Add<&M31LimbsBar> for &M31LimbsBar {
    type Output = M31LimbsBar;

    fn add(self, rhs: &M31LimbsBar) -> Self::Output {
        let new_limbs = M31Limbs::add_limbs(&self.value, &rhs.value);

        let cs = self.cs().and(&rhs.cs());
        cs.insert_script(
            M31LimbsGadget::add_limbs,
            self.variables().iter().chain(rhs.variables.iter()).copied(),
        )
        .unwrap();

        M31LimbsBar::new_function_output(
            &cs,
            [new_limbs[0], new_limbs[1], new_limbs[2], new_limbs[3]],
        )
        .unwrap()
    }
}

pub fn m31_to_limbs_gadget() -> Script {
    // input: m31_var, limb1..4
    script! {
        check_limb_format
        OP_256MUL OP_SWAP
        check_limb_format OP_ADD

        OP_256MUL OP_SWAP
        check_limb_format OP_ADD

        OP_256MUL OP_SWAP
        check_limb_format OP_ADD

        OP_EQUALVERIFY
    }
}

fn m31_limbs_mul_gadget(stack: &mut Stack, options: &Options) -> Result<Script> {
    let last_table_elem = options.get_u32("table_ref")?;
    let k = stack.get_relative_position(last_table_elem as usize)? - 512;

    Ok(script! {
        OP_TOALTSTACK
        { M31MultGadget::compute_c_limbs(k) }
        OP_FROMALTSTACK
        { M31MultGadget::reduce() }
    })
}

#[cfg(test)]
mod test {
    use crate::fields::m31::M31Bar;
    use crate::fields::m31_limbs::M31LimbsBar;
    use crate::fields::table::m31::M31Limbs;
    use crate::fields::table::utils::convert_m31_to_limbs;
    use crate::fields::table::TableBar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use recursive_stwo_bitcoin_dsl::{rand_m31, test_program};

    #[test]
    fn test_m31_to_limbs() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_m31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = M31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = M31LimbsBar::from(&a);

        cs.set_program_output(&a_limbs).unwrap();

        test_program(
            cs,
            script! {
                { convert_m31_to_limbs(a_val).to_vec() }
            },
        )
        .unwrap();
    }

    #[test]
    fn test_m31_limbs_equalverify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_m31(&mut prng);
        let cs = BitcoinSystemRef::new_ref();

        let a = M31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = M31LimbsBar::from(&a);
        let a2_limbs = M31LimbsBar::from(&a);

        a_limbs.equalverify(&a2_limbs).unwrap();

        test_program(cs, script! {}).unwrap();
    }

    #[test]
    fn test_m31_limbs_table_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_m31(&mut prng);
        let b_val = rand_m31(&mut prng);
        let cs = BitcoinSystemRef::new_ref();

        let a = M31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = M31LimbsBar::from(&a);

        let b = M31Bar::new_constant(&cs, b_val).unwrap();
        let b_limbs = M31LimbsBar::from(&b);

        let table = TableBar::new_constant(&cs, ()).unwrap();
        let res = &a_limbs * (&table, &b_limbs);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                { a_val * b_val }
            },
        )
        .unwrap();
    }

    #[test]
    fn test_m31_limbs_inverse() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_m31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a = M31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs = M31LimbsBar::from(&a);

        let table = TableBar::new_constant(&cs, ()).unwrap();

        let a_inv_limbs = a_limbs.inverse(&table);

        let res = &a_limbs * (&table, &a_inv_limbs);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                1
            },
        )
        .unwrap();
    }

    #[test]
    fn test_m31_limbs_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_m31(&mut prng);
        let b_val = rand_m31(&mut prng);

        let cs = BitcoinSystemRef::new_ref();

        let a_var = M31Bar::new_constant(&cs, a_val).unwrap();
        let a_limbs_var = M31LimbsBar::from(&a_var);
        let b_var = M31Bar::new_constant(&cs, b_val).unwrap();
        let b_limbs_var = M31LimbsBar::from(&b_var);

        let a_limbs = convert_m31_to_limbs(a_val);
        let b_limbs = convert_m31_to_limbs(b_val);
        let sum_limbs = M31Limbs::add_limbs(&a_limbs, &b_limbs);

        let sum_limbs_var = &a_limbs_var + &b_limbs_var;
        cs.set_program_output(&sum_limbs_var).unwrap();

        test_program(
            cs,
            script! {
                { sum_limbs }
            },
        )
        .unwrap();
    }
}
