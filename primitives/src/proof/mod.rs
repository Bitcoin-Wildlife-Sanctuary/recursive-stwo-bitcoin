use crate::channel::ChannelBar;
use crate::m31::M31Bar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::examples::plonk_with_poseidon::air::PlonkWithPoseidonStatement0;

#[derive(Debug, Clone)]
pub struct PlonkWithPoseidonStatement0Bar {
    pub log_size_plonk: M31Bar,
    pub log_size_poseidon: M31Bar,
}

impl AllocBar for PlonkWithPoseidonStatement0Bar {
    type Value = PlonkWithPoseidonStatement0;

    fn value(&self) -> Result<Self::Value> {
        Ok(PlonkWithPoseidonStatement0 {
            log_size_poseidon: self.log_size_poseidon.value.0,
            log_size_plonk: self.log_size_plonk.value.0,
        })
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let log_size_poseidon = M31Bar::new_variable(cs, M31::from(data.log_size_poseidon), mode)?;
        let log_size_plonk = M31Bar::new_variable(cs, M31::from(data.log_size_plonk), mode)?;

        Ok(Self {
            log_size_poseidon,
            log_size_plonk,
        })
    }
}

impl PlonkWithPoseidonStatement0Bar {
    pub fn mix_into<T: ChannelBar>(&self, channel: &mut T) {}
}
