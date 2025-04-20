use recursive_stwo_primitives::circle::precomputed::PrecomputedTree;
use std::path::PathBuf;

fn main() {
    PrecomputedTree::gen_subtrees(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/precomputed_tree.bin"),
    )
    .unwrap();
}
