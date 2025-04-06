use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;

pub fn generate_cs(ldm_delegated: &mut LDM, ldm: &mut LDM) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm_delegated.init(&cs)?;
    ldm.init(&cs)?;

    ldm_delegated.check()?;

    ldm.save()?;
    Ok(cs)
}
