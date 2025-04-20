use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::ops::Neg;
use std::path::PathBuf;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::core::vcs::bitcoin_num_to_bytes;

use crate::bits::split_be_bits;
use crate::circle::CirclePointM31Bar;
use crate::fields::m31::M31Bar;
use rayon::prelude::*;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;

// 2^28 -> 2^18 subtress, each 2^10
pub struct PrecomputedTree;

impl PrecomputedTree {
    pub fn gen_subtrees(subtree_path: PathBuf) -> Result<()> {
        let mut file = BufWriter::new(std::fs::File::create(subtree_path)?);

        let commitment_domain_big = CanonicCoset::new(28).circle_domain();
        let commitment_domain_small = CanonicCoset::new(26).circle_domain();
        for i in 0..(1 << 18) {
            let mut layer = (0..1 << 10)
                .into_par_iter()
                .map(|j| {
                    let mut sha256 = Sha256::new();
                    let index = (i << 10) + j;
                    let domain_point = commitment_domain_big.at(bit_reverse_index(index, 28));
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.x));
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y));
                    if index % 2 == 0 {
                        Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y.inverse()));
                    } else {
                        Digest::update(
                            &mut sha256,
                            bitcoin_num_to_bytes(domain_point.y.neg().inverse()),
                        );
                    }

                    let hash: [u8; 32] = sha256.finalize().into();
                    hash
                })
                .collect::<Vec<_>>();

            // skip layer 27
            layer = layer
                .par_chunks_exact(2)
                .map(|c| {
                    let mut sha256 = Sha256::new();
                    Digest::update(&mut sha256, &c[0]);
                    Digest::update(&mut sha256, &c[1]);
                    let hash: [u8; 32] = sha256.finalize().into();
                    hash
                })
                .collect::<Vec<_>>();

            layer = (0..1 << 8)
                .into_par_iter()
                .map(|j| {
                    let mut sha256 = Sha256::new();
                    let index = (i << 8) + j;
                    let domain_point = commitment_domain_small.at(bit_reverse_index(index, 26));
                    Digest::update(&mut sha256, &layer[j * 2]);
                    Digest::update(&mut sha256, &layer[j * 2 + 1]);
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.x));
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y));
                    if index % 2 == 0 {
                        Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y.inverse()));
                    } else {
                        Digest::update(
                            &mut sha256,
                            bitcoin_num_to_bytes(domain_point.y.neg().inverse()),
                        );
                    }

                    let hash: [u8; 32] = sha256.finalize().into();
                    hash
                })
                .collect::<Vec<_>>();

            for _ in 0..8 {
                layer = layer
                    .par_chunks_exact(2)
                    .map(|c| {
                        let mut sha256 = Sha256::new();
                        Digest::update(&mut sha256, &c[0]);
                        Digest::update(&mut sha256, &c[1]);
                        let hash: [u8; 32] = sha256.finalize().into();
                        hash
                    })
                    .collect::<Vec<_>>();
            }
            assert_eq!(layer.len(), 1);
            file.write(&layer[0])?;
        }

        file.flush()?;

        Ok(())
    }

    pub fn build_subtree(i: usize) -> Result<Tree> {
        let mut layers = vec![];

        let commitment_domain_big = CanonicCoset::new(28).circle_domain();
        let commitment_domain_small = CanonicCoset::new(26).circle_domain();
        let mut layer = (0..1 << 10)
            .into_par_iter()
            .map(|j| {
                let mut sha256 = Sha256::new();
                let index = (i << 10) + j;
                let domain_point = commitment_domain_big.at(bit_reverse_index(index, 28));
                Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.x));
                Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y));
                if index % 2 == 0 {
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y.inverse()));
                } else {
                    Digest::update(
                        &mut sha256,
                        bitcoin_num_to_bytes(domain_point.y.neg().inverse()),
                    );
                }

                let hash: [u8; 32] = sha256.finalize().into();
                hash
            })
            .collect::<Vec<_>>();
        layers.push(layer.clone());

        // skip layer 27
        layer = layer
            .par_chunks_exact(2)
            .map(|c| {
                let mut sha256 = Sha256::new();
                Digest::update(&mut sha256, &c[0]);
                Digest::update(&mut sha256, &c[1]);
                let hash: [u8; 32] = sha256.finalize().into();
                hash
            })
            .collect::<Vec<_>>();
        layers.push(layer.clone());

        layer = (0..1 << 8)
            .into_par_iter()
            .map(|j| {
                let mut sha256 = Sha256::new();
                let index = (i << 8) + j;
                let domain_point = commitment_domain_small.at(bit_reverse_index(index, 26));
                Digest::update(&mut sha256, &layer[j * 2]);
                Digest::update(&mut sha256, &layer[j * 2 + 1]);
                Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.x));
                Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y));
                if index % 2 == 0 {
                    Digest::update(&mut sha256, bitcoin_num_to_bytes(domain_point.y.inverse()));
                } else {
                    Digest::update(
                        &mut sha256,
                        bitcoin_num_to_bytes(domain_point.y.neg().inverse()),
                    );
                }

                let hash: [u8; 32] = sha256.finalize().into();
                hash
            })
            .collect::<Vec<_>>();
        layers.push(layer.clone());

        for _ in 0..8 {
            layer = layer
                .par_chunks_exact(2)
                .map(|c| {
                    let mut sha256 = Sha256::new();
                    Digest::update(&mut sha256, &c[0]);
                    Digest::update(&mut sha256, &c[1]);
                    let hash: [u8; 32] = sha256.finalize().into();
                    hash
                })
                .collect::<Vec<_>>();
            layers.push(layer.clone());
        }
        assert_eq!(layer.len(), 1);

        Ok(Tree { layers })
    }

    pub fn build_upper_tree(subtree_path: PathBuf) -> Result<Tree> {
        let mut layers = vec![];

        let mut file = BufReader::new(std::fs::File::open(subtree_path)?);
        let mut layer = Vec::<[u8; 32]>::with_capacity(1 << 18);
        for _ in 0..(1 << 18) {
            let mut buf = [0u8; 32];
            file.read(&mut buf)?;
            layer.push(buf);
        }
        layers.push(layer.clone());

        while layer.len() != 1 {
            layer = layer
                .par_chunks_exact(2)
                .map(|c| {
                    let mut sha256 = Sha256::new();
                    Digest::update(&mut sha256, &c[0]);
                    Digest::update(&mut sha256, &c[1]);
                    sha256.finalize().into()
                })
                .collect::<Vec<_>>();
            layers.push(layer.clone());
        }

        Ok(Tree { layers })
    }
}

pub struct Tree {
    pub layers: Vec<Vec<[u8; 32]>>,
}

impl Tree {
    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    pub fn path(&self, index: usize) -> TreePath {
        let mut siblings = vec![];
        let mut cur = index;
        for layer in self.layers.iter().take(self.layers.len() - 1) {
            siblings.push(layer[cur ^ 1]);
            cur >>= 1;
        }
        assert_eq!(cur, 0);

        TreePath { index, siblings }
    }

    pub fn subtree_verify(
        root: &[u8; 32],
        path: &TreePath,
        point1: &CirclePoint<M31>,
        point2: &CirclePoint<M31>,
    ) -> Result<()> {
        // compute layer 28
        let mut cur_index = path.index;

        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, bitcoin_num_to_bytes(point1.x));
        Digest::update(&mut sha256, bitcoin_num_to_bytes(point1.y));
        if cur_index % 2 == 0 {
            Digest::update(&mut sha256, bitcoin_num_to_bytes(point1.y.inverse()));
        } else {
            Digest::update(&mut sha256, bitcoin_num_to_bytes(point1.y.neg().inverse()));
        }
        let mut hash: [u8; 32] = sha256.finalize().into();

        // compute layer 27
        let mut sha256 = Sha256::new();
        if cur_index % 2 == 0 {
            Digest::update(&mut sha256, &hash);
            Digest::update(&mut sha256, &path.siblings[0]);
        } else {
            Digest::update(&mut sha256, &path.siblings[0]);
            Digest::update(&mut sha256, &hash);
        }
        cur_index = cur_index >> 1;
        hash = sha256.finalize().into();

        // compute layer 26
        let mut sha256 = Sha256::new();
        if cur_index % 2 == 0 {
            Digest::update(&mut sha256, &hash);
            Digest::update(&mut sha256, &path.siblings[1]);
        } else {
            Digest::update(&mut sha256, &path.siblings[1]);
            Digest::update(&mut sha256, &hash);
        }
        cur_index = cur_index >> 1;
        Digest::update(&mut sha256, bitcoin_num_to_bytes(point2.x));
        Digest::update(&mut sha256, bitcoin_num_to_bytes(point2.y));
        if cur_index % 2 == 0 {
            Digest::update(&mut sha256, bitcoin_num_to_bytes(point2.y.inverse()));
        } else {
            Digest::update(&mut sha256, bitcoin_num_to_bytes(point2.y.neg().inverse()));
        }
        hash = sha256.finalize().into();

        for i in 0..8 {
            let mut sha256 = Sha256::new();
            if cur_index % 2 == 0 {
                Digest::update(&mut sha256, &hash);
                Digest::update(&mut sha256, &path.siblings[i + 2]);
            } else {
                Digest::update(&mut sha256, &path.siblings[i + 2]);
                Digest::update(&mut sha256, &hash);
            }
            cur_index = cur_index >> 1;
            hash = sha256.finalize().into();
        }

        assert_eq!(hash, *root);
        assert_eq!(cur_index, 0);

        Ok(())
    }

    pub fn upper_tree_verify(
        root: &[u8; 32],
        path: &TreePath,
        subtree_root: &[u8; 32],
    ) -> Result<()> {
        let mut cur_index = path.index;
        let mut hash = subtree_root.clone();
        for sibling in path.siblings.iter() {
            let mut sha256 = Sha256::new();
            if cur_index % 2 == 0 {
                Digest::update(&mut sha256, &hash);
                Digest::update(&mut sha256, &sibling);
            } else {
                Digest::update(&mut sha256, &sibling);
                Digest::update(&mut sha256, &hash);
            }
            cur_index = cur_index >> 1;
            hash = sha256.finalize().into();
        }

        assert_eq!(hash, *root);
        assert_eq!(cur_index, 0);

        Ok(())
    }
}

pub struct TreePath {
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

pub struct PrecomputedTreeResultVar {
    pub point_28: CirclePointM31Bar,
    pub point_28_y_inv: M31Bar,
    pub point_26: CirclePointM31Bar,
    pub point_26_y_inv: M31Bar,
}

impl PrecomputedTreeResultVar {
    pub fn fetch_and_verify(upper_tree: &Tree, index: &M31Bar) -> Result<PrecomputedTreeResultVar> {
        let commitment_domain_big = CanonicCoset::new(28).circle_domain();
        let commitment_domain_small = CanonicCoset::new(26).circle_domain();

        let index_value = index.value()?.0 as usize;

        let cs = index.cs();

        let point_28_value = commitment_domain_big.at(bit_reverse_index(index_value, 28));
        let point_26_value = commitment_domain_small.at(bit_reverse_index(index_value >> 2, 26));

        let point_28_y_inv_value = if index_value % 2 == 0 {
            point_28_value.y.inverse()
        } else {
            point_28_value.y.neg().inverse()
        };

        let point_26_y_inv_value = if (index_value >> 2) % 2 == 0 {
            point_26_value.y.inverse()
        } else {
            point_26_value.y.neg().inverse()
        };

        let point_28 = CirclePointM31Bar::new_hint(&cs, (point_28_value.x, point_28_value.y))?;
        let point_26 = CirclePointM31Bar::new_hint(&cs, (point_26_value.x, point_26_value.y))?;

        let point_28_y_inv = M31Bar::new_hint(&cs, point_28_y_inv_value)?;
        let point_26_y_inv = M31Bar::new_hint(&cs, point_26_y_inv_value)?;

        let subtree = PrecomputedTree::build_subtree(index_value >> 10).unwrap();
        let subtree_path = subtree.path(index_value & ((1 << 10) - 1));
        assert!(Tree::subtree_verify(
            &subtree.root(),
            &subtree_path,
            &point_28_value,
            &point_26_value
        )
        .is_ok());

        let mut cur =
            &(&point_28.x.to_str()? + &point_28.y.to_str()?) + &point_28_y_inv.to_str()?;
        cur = cur.hash()?;

        let bits = split_be_bits(&index, 28)?;

        let (lhs, rhs) = StrBar::swap(
            &cur,
            &StrBar::new_hint(&cs, subtree_path.siblings[0].to_vec())?,
            &bits[0],
        )?;
        cur = &lhs + &rhs;
        cur = cur.hash()?;

        let (lhs, rhs) = StrBar::swap(
            &cur,
            &StrBar::new_hint(&cs, subtree_path.siblings[1].to_vec())?,
            &bits[1],
        )?;
        cur = &lhs + &rhs;
        cur = &cur + &point_26.x.to_str()?;
        cur = &cur + &point_26.y.to_str()?;
        cur = &cur + &point_26_y_inv.to_str()?;
        cur = cur.hash()?;

        for i in 0..8 {
            let (lhs, rhs) = StrBar::swap(
                &cur,
                &StrBar::new_hint(&cs, subtree_path.siblings[i + 2].to_vec())?,
                &bits[i + 2],
            )?;
            cur = &lhs + &rhs;
            cur = cur.hash()?;
        }

        let subtree_root = StrBar::new_constant(&cs, subtree.root().to_vec())?;
        cur.equalverify(&subtree_root)?;

        let upper_tree_path = upper_tree.path(index_value >> 10);

        for i in 0..18 {
            let (lhs, rhs) = StrBar::swap(
                &cur,
                &StrBar::new_hint(&cs, upper_tree_path.siblings[i].to_vec())?,
                &bits[10 + i],
            )?;
            cur = &lhs + &rhs;
            cur = cur.hash()?;
        }

        let upper_tree_root = StrBar::new_constant(&cs, upper_tree.root().to_vec())?;
        cur.equalverify(&upper_tree_root)?;

        Ok(PrecomputedTreeResultVar {
            point_28,
            point_28_y_inv,
            point_26,
            point_26_y_inv,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::circle::precomputed::{PrecomputedTree, PrecomputedTreeResultVar, Tree};
    use crate::fields::m31::M31Bar;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use std::path::PathBuf;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::poly::circle::CanonicCoset;
    use stwo_prover::core::utils::bit_reverse_index;

    #[test]
    fn test_subtree_verify() {
        let mut prng = StdRng::seed_from_u64(0);
        for _ in 0..10 {
            let index = prng.gen_range(0..(1 << 28)) as usize;

            let subtree = PrecomputedTree::build_subtree(index >> 10).unwrap();
            let path = subtree.path(index & ((1 << 10) - 1));

            let commitment_domain_big = CanonicCoset::new(28).circle_domain();
            let commitment_domain_small = CanonicCoset::new(26).circle_domain();

            let point1 = commitment_domain_big.at(bit_reverse_index(index, 28));
            let point2 = commitment_domain_small.at(bit_reverse_index(index >> 2, 26));

            Tree::subtree_verify(&subtree.root(), &path, &point1, &point2).unwrap();
        }
    }

    #[test]
    fn test_upper_tree_verify() {
        let mut prng = StdRng::seed_from_u64(0);
        let upper_tree = PrecomputedTree::build_upper_tree(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/precomputed_tree.bin"),
        )
        .unwrap();

        for _ in 0..10 {
            let index = prng.gen_range(0..(1 << 28)) as usize;

            let subtree = PrecomputedTree::build_subtree(index >> 10).unwrap();
            assert_eq!(subtree.root(), upper_tree.layers[0][index >> 10]);

            let path = upper_tree.path(index >> 10);
            Tree::upper_tree_verify(&upper_tree.root(), &path, &subtree.root()).unwrap();
        }
    }

    #[test]
    fn test_fetch_and_verify() {
        let mut prng = StdRng::seed_from_u64(0);
        let upper_tree = PrecomputedTree::build_upper_tree(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/precomputed_tree.bin"),
        )
        .unwrap();

        for _ in 0..10 {
            let index_value = prng.gen_range(0..(1 << 28)) as usize;

            let cs = BitcoinSystemRef::new_ref();
            let index = M31Bar::new_hint(&cs, M31::from(index_value)).unwrap();
            let _ = PrecomputedTreeResultVar::fetch_and_verify(&upper_tree, &index).unwrap();
            test_program(cs, script! {}).unwrap();
        }
    }
}
