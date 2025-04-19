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

    // The formula for the x coordinate of the double of a point.
    for _ in 11..17 {
        let sq = &x * (&table, &x);
        x = (&sq + &sq).sub1();
    }
    x = x.inverse(&table);
    ldm.write("coset_vanishing_x_inv", &x)?;

    ldm.save()?;
    Ok(cs)
}
