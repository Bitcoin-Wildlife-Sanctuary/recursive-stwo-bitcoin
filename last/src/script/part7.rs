use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::circle::CirclePointQM31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let oods_t: QM31Bar = ldm.read("oods_t")?;
    let table = TableBar::new_constant(&cs, ())?;

    let oods_point = CirclePointQM31Bar::from_t(&table, &oods_t);
    ldm.write("oods_x", &oods_point.x)?;
    ldm.write("oods_y", &oods_point.y)?;

    let coset = CanonicCoset::new(proof.stmt0.log_size_plonk).coset;
    let mut x = (&oods_point
        + (
            &table,
            &(-coset.initial + coset.step_size.half().to_point()),
        ))
        .x;

    assert_eq!(coset.log_size, 17);
    // The formula for the x coordinate of the double of a point.
    for _ in 1..3 {
        let sq = &x * (&table, &x);
        x = (&sq + &sq).sub1();
    }
    ldm.write("coset_vanishing_x_part7", &x)?;

    ldm.save()?;
    Ok(cs)
}
