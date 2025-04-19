use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use std::ops::Neg;
use std::path::PathBuf;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::utils::bit_reverse_index;
use stwo_prover::core::vcs::bitcoin_num_to_bytes;

use rayon::prelude::*;

// 2^28 -> 2^18 subtress, each 2^10
pub struct PrecomputedTree {
    pub layers: Vec<[u8; 32]>,
}

impl PrecomputedTree {
    pub fn gen_subtrees(subtree_path: PathBuf) -> Result<()> {
        let mut file = BufWriter::new(std::fs::File::create(subtree_path)?);

        let commitment_domain = CanonicCoset::new(28).circle_domain();
        for i in 0..(1 << 18) {
            let mut layer = (0..1 << 10)
                .into_par_iter()
                .map(|j| {
                    let mut sha256 = Sha256::new();
                    let index = (i << 10) + j;
                    let domain_point = commitment_domain.at(bit_reverse_index(index, 28));
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
                    let domain_point = commitment_domain.at(bit_reverse_index(index, 26));
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

    pub fn build_upper_tree(subtree_path: PathBuf) -> Result<()> {
        todo!()
    }
}
