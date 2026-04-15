//! PlonkWithPoseidon Coset Vanishing Script Part 9
//!
//! Completes the coset vanishing computation.
//! Does doublings 9-11 (3 iterations) and computes the inverse.

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut x: QM31Bar = ldm.read("coset_vanishing_x_part8")?;
    let table = TableBar::new_constant(&cs, ())?;

    // Final doublings 11-15 (5 iterations)
    // For log_size=15, total = 15 doublings
    // After this: all 15 doublings complete
    for _ in 11..=15 {
        let sq = &x * (&table, &x);
        x = (&sq + &sq).sub1();
    }

    // Compute the inverse for the vanishing polynomial
    x = x.inverse(&table);
    ldm.write("coset_vanishing_x_inv", &x)?;

    ldm.save()?;
    Ok(cs)
}
