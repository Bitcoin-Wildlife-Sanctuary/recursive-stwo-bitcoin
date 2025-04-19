use recursive_stwo_primitives::circle::precomputed::PrecomputedTree;
use std::path::PathBuf;

fn main() {
    PrecomputedTree::gen(PathBuf::from("../data/precomputed_tree.bin")).unwrap();
}
