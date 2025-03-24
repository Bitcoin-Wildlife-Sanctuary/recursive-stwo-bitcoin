use anyhow::Result;
use bitcoin::opcodes::Ordinary::{OP_GREATERTHANOREQUAL, OP_LESSTHANOREQUAL, OP_VERIFY};
use bitcoin_scriptexec::{profiler_end, profiler_start};
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use sha2::{Digest, Sha256};

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
