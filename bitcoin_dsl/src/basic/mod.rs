use crate::treepp::Script;
use bitcoin::opcodes::all::OP_RETURN;

pub mod bool;
pub mod i32;
pub mod sha256_hash;
pub mod str;
pub mod u8;

#[allow(unused)]
pub(crate) fn return_script() -> Script {
    Script::from(vec![OP_RETURN.to_u8()])
}
