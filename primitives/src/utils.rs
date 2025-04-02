use crate::fields::m31::M31Bar;
use anyhow::Result;
use bitcoin_scriptexec::{profiler_end, profiler_start};
use itertools::Itertools;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::{bitcoin_num_to_bytes, Sha256HashBar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use sha2::{Digest, Sha256};
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

/// Trim a m31 element to have only logn bits.
pub fn trim_m31(v: u32, logn: usize) -> u32 {
    v & ((1 << logn) - 1)
}

/// Call the selected hash function.
pub fn hash() -> Script {
    script! {
        { profiler_start("op_sha256") } OP_SHA256 { profiler_end("op_sha256") }
    }
}

/// Stop the script for debugging.
pub fn debug_return() -> Script {
    script! {
        OP_RETURN
    }
}

/// Gadget for hashing k m31 elements (in the case of qm31, k = 4) in the script.
pub fn hash_m31_vec_gadget(len: usize) -> Script {
    if len == 0 {
        script! {
            { Sha256::new().finalize().to_vec() }
        }
    } else {
        script! {
            hash
            for _ in 1..len {
                OP_CAT hash
            }
        }
    }
}

/// Gadget for hashing a qm31 element.
pub fn hash_qm31_gadget() -> Script {
    hash_m31_vec_gadget(4)
}

pub fn hash_many_m31(cs: &BitcoinSystemRef, elems: &[M31Bar]) -> Result<Sha256HashBar> {
    let mut hash = [0u8; 32];

    let mut sha256 = sha2::Sha256::new();
    Digest::update(&mut sha256, bitcoin_num_to_bytes(elems[0].value.0 as i64));
    hash.copy_from_slice(sha256.finalize().as_slice());

    for i in 1..elems.len() {
        let mut sha256 = sha2::Sha256::new();
        Digest::update(&mut sha256, bitcoin_num_to_bytes(elems[i].value.0 as i64));
        Digest::update(&mut sha256, &hash);
        hash.copy_from_slice(sha256.finalize().as_slice());
    }

    cs.insert_script_complex(
        hash_many_m31_gadget,
        elems.iter().rev().map(|v| v.variable).collect_vec(),
        &Options::new().with_u32("n", elems.len() as u32),
    )?;

    let result = Sha256HashBar::new_function_output(&cs, Sha256Hash::from(hash.as_slice()))?;
    Ok(result)
}

/// Gadget to hash multiple m31 elements.
pub fn hash_many_m31_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let k = options.get_u32("n")?;
    Ok(script! {
        OP_SHA256
        for _ in 1..k {
            OP_CAT OP_SHA256
        }
    })
}

pub fn drop_gadget() -> Script {
    script! {
        OP_DROP
    }
}
