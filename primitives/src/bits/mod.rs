use crate::fields::m31::M31Bar;
use anyhow::Result;
use bitcoin::opcodes::Ordinary::{OP_DUP, OP_ELSE, OP_TOALTSTACK};
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::bool::BoolBar;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use stwo_prover::core::fields::m31::M31;

pub fn enforce_bit_range(a: &M31Bar, log_size: usize) {
    assert!(a.value.0 <= ((1 << log_size) - 1));
    a.cs.insert_script_complex(
        enforce_bit_range_gadget,
        [a.variable],
        &Options::new().with_u32("log_size", log_size as u32),
    )
    .unwrap();
}

/// Gadget for enforcing the number of bits of a number.
fn enforce_bit_range_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let log_size = options.get_u32("log_size")?;
    let max = (1 << log_size) - 1;

    Ok(script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP { max } OP_LESSTHANOREQUAL OP_VERIFY
    })
}

pub fn split_hi_lo(a: &M31Bar, log_size: usize) -> Result<(M31Bar, M31Bar)> {
    let hi = a.value.0 >> log_size;
    let lo = a.value.0 & ((1 << log_size) - 1);
    debug_assert_eq!(a.value.0, (hi << log_size) + lo);

    let cs = a.cs.clone();

    let hi_var = M31Bar::new_hint(&cs, M31::from(hi))?;
    let lo_var = M31Bar::new_hint(&cs, M31::from(lo))?;

    enforce_bit_range(&hi_var, 31 - log_size);
    enforce_bit_range(&lo_var, log_size);

    cs.insert_script_complex(
        get_lo_gadget,
        [a.variable, lo_var.variable, hi_var.variable],
        &Options::new().with_u32("log_size", log_size as u32),
    )?;

    Ok((hi_var, lo_var))
}

fn get_lo_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let log_size = options.get_u32("log_size")?;
    Ok(script! {
        for _ in 0..log_size {
            OP_DUP OP_ADD
        }
        OP_ADD
        OP_EQUALVERIFY
    })
}

pub fn split_be_bits(a: &M31Bar, log_size: usize) -> Result<Vec<BoolBar>> {
    let mut bits = vec![];

    let mut cur = a.value.0;
    for _ in 0..log_size {
        bits.push(cur & 1);
        cur >>= 1;
    }

    todo!()
}

fn split_be_bits_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let log_size = options.get_u32("log_size")?;
    Ok(script! {
        // stack:
        //   num (assumed within log_size bits)

        for i in (1..log_size).rev() {
            OP_DUP
            { 1 << i } OP_GREATERTHANOREQUAL
            OP_IF
                1 OP_TOALTSTACK
                { 1 << i } OP_SUB
            OP_ELSE

            OP_ENDIF
        }
    })
}
