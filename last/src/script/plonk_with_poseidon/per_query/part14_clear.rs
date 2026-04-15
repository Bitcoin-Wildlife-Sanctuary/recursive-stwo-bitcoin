//! PlonkWithPoseidon Per-Query Part 14: Clear State
//!
//! This script clears the per-query LDM state after successful verification.
//! It's the final script for each query.

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;

pub fn generate_cs(
    ldm: &mut LDM,
    _ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    // Clear per-query state by not reading anything from it
    // The ldm_per_query will be reset for the next query

    ldm.save()?;
    Ok(cs)
}
