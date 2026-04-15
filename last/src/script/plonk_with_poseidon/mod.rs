//! Bitcoin script verification for PlonkWithPoseidon proofs
//!
//! This module provides the infrastructure to verify `PlonkWithPoseidonProof<Sha256MerkleHasher>`
//! proofs on Bitcoin using covenant scripts.
//!
//! Key differences from PlonkWithoutPoseidon:
//! - 130 columns (vs 28): requires more scripts for line coefficients and decommitments
//! - Dual log_size: PLONK and Poseidon sub-circuits may have different sizes
//! - Two total_sums: plonk_total_sum and poseidon_total_sum
//!
//! Column structure:
//! - Preprocessed: 50 (10 PLONK + 40 Poseidon)
//! - Trace: 60 (12 PLONK + 48 Poseidon)
//! - Interaction: 16 (8 PLONK + 8 Poseidon)
//! - Composition: 4

pub mod labels;
pub mod hints;
pub mod decommit;
pub mod answer;
pub mod fri_hints;
pub mod global;
pub mod per_query;

#[cfg(test)]
mod test_stack_limits;

pub use labels::*;
pub use hints::*;
pub use decommit::*;
pub use answer::*;
pub use fri_hints::*;
