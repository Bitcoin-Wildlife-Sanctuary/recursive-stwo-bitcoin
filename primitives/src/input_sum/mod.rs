use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use serde::{Deserialize, Serialize};
use stwo_prover::core::fields::qm31::QM31;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputSum {
    pub alpha: QM31,
    pub cur: QM31,
    pub sum: QM31,
}

impl InputSum {
    pub fn new(alpha: QM31, z: QM31) -> Self {
        InputSum {
            alpha,
            cur: alpha - z,
            sum: QM31::zero(),
        }
    }
}

#[derive(Clone)]
pub struct InputSumBar {
    pub alpha: QM31Bar,
    pub cur: QM31Bar,
    pub sum: QM31Bar,
}

impl AllocBar for InputSumBar {
    type Value = InputSum;

    fn value(&self) -> Result<Self::Value> {
        Ok(InputSum {
            alpha: self.alpha.value()?,
            cur: self.cur.value()?,
            sum: self.sum.value()?,
        })
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let alpha = QM31Bar::new_variable(cs, data.alpha, mode)?;
        let cur = QM31Bar::new_variable(cs, data.cur, mode)?;
        let sum = QM31Bar::new_variable(cs, data.sum, mode)?;

        Ok(Self { alpha, cur, sum })
    }
}

impl InputSumBar {
    pub fn new(z: &QM31Bar, alpha: &QM31Bar) -> Result<Self> {
        let cs = z.cs().and(&alpha.cs());
        Ok(InputSumBar {
            alpha: alpha.clone(),
            cur: alpha - z,
            sum: QM31Bar::new_constant(&cs, QM31::zero())?,
        })
    }

    pub fn accumulate_from_ldm(
        &mut self,
        table: &TableBar,
        ldm: &mut LDM,
        name: impl ToString,
    ) -> Result<()> {
        let new_elem: QM31Bar = ldm.read(name)?;
        self.accumulate(table, &new_elem);
        Ok(())
    }

    pub fn accumulate(&mut self, table: &TableBar, v: &QM31Bar) {
        self.sum = &self.sum + &(&self.cur + v).inverse(table);
        self.cur = &self.cur + &self.alpha;
    }
}
