//! PlonkWithPoseidon Coset Vanishing Script Part 7
//!
//! Computes the coset vanishing polynomial evaluation at the OODS point.
//! For log_size_plonk=15, coset.log_size = 11 (15 - 4).
//!
//! This script:
//! 1. Converts oods_t to oods_point
//! 2. Shifts by coset initial point
//! 3. Does first 2 doublings (iterations 1-2)

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::circle::CirclePointQM31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let oods_t: QM31Bar = ldm.read("oods_t")?;
    let table = TableBar::new_constant(&cs, ())?;

    // Convert oods_t to oods_point on the circle
    let oods_point = CirclePointQM31Bar::from_t(&table, &oods_t);
    ldm.write("oods_x", &oods_point.x)?;
    ldm.write("oods_y", &oods_point.y)?;

    // Get the coset for log_size_plonk
    // For log_size=15, coset.log_size = 11
    let coset = CanonicCoset::new(proof.stmt0.log_size_plonk).coset;

    // Shift oods_point by coset offset
    let mut x = (&oods_point
        + (
            &table,
            &(-coset.initial + coset.step_size.half().to_point()),
        ))
        .x;

    // Verify coset.log_size matches log_size_plonk
    assert_eq!(
        coset.log_size,
        proof.stmt0.log_size_plonk,
        "Unexpected coset log_size: {} for log_size_plonk: {}",
        coset.log_size,
        proof.stmt0.log_size_plonk
    );

    // First 2 doublings (iterations 1-2)
    // Total needed: coset.log_size = 15 doublings for log_size_plonk=15
    for _ in 1..=2 {
        let sq = &x * (&table, &x);
        x = (&sq + &sq).sub1();
    }

    ldm.write("coset_vanishing_x_part7", &x)?;

    ldm.save()?;
    Ok(cs)
}
