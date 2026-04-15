//! PlonkWithPoseidon Coset Vanishing Script Part 8
//!
//! Continues the coset vanishing computation.
//! Does doublings 3-8 (6 iterations).

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;

pub fn generate_cs(ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut x: QM31Bar = ldm.read("coset_vanishing_x_part7")?;
    let table = TableBar::new_constant(&cs, ())?;

    // Doublings 3-10 (8 iterations)
    // For log_size=15, total needed = 15
    // After part7: 2 done, 13 remaining
    // After part8: 10 done, 5 remaining
    for _ in 3..=10 {
        let sq = &x * (&table, &x);
        x = (&sq + &sq).sub1();
    }

    ldm.write("coset_vanishing_x_part8", &x)?;

    ldm.save()?;
    Ok(cs)
}
