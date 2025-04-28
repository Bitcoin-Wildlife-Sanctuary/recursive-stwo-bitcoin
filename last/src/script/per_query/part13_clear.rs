use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;

pub fn generate_cs(ldm: &mut LDM, ldm_per_query: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    ldm_per_query.check()?;

    ldm.save()?;
    Ok(cs)
}
