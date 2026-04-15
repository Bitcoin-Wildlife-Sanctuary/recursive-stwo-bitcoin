//! Global Bitcoin scripts for PlonkWithPoseidon verification
//!
//! These scripts run once per proof verification, setting up the channel state,
//! computing challenges, and verifying the STARK composition.
//!
//! Script sequence:
//! - part1_fiat_shamir: Mix commitments, draw z/alpha
//! - part2_fiat_shamir: Total sums, interaction/composition commitments, oods_t
//! - part3_fiat_shamir: Preprocessed columns (50)
//! - part4_fiat_shamir: Trace columns (60)
//! - part5_fiat_shamir: Interaction columns (16) + composition columns (4)
//! - part6_fiat_shamir: FRI commitments, PoW, queries

pub mod part1_fiat_shamir;
pub mod part2_fiat_shamir;
pub mod part3_fiat_shamir;
pub mod part4_fiat_shamir;
pub mod part5_fiat_shamir;
pub mod part6_fiat_shamir;
pub mod part7_coset_vanishing;
pub mod part8_coset_vanishing;
pub mod part9_coset_vanishing;
pub mod part10_logup;
pub mod part11_point_shift;
pub mod line_coeffs;

#[cfg(test)]
mod tests;
