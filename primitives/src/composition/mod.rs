use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use stwo_prover::core::fields::qm31::QM31;

pub struct PointEvaluationAccumulatorBar {
    pub random_coeff: QM31Bar,
    pub accumulation: QM31Bar,
}

impl PointEvaluationAccumulatorBar {
    pub fn new(random_coeff: &QM31Bar) -> Result<Self> {
        Ok(Self {
            random_coeff: random_coeff.clone(),
            accumulation: QM31Bar::new_constant(&random_coeff.cs(), QM31::zero())?,
        })
    }

    pub fn accumulate(&mut self, table: &TableBar, evaluation: &QM31Bar) {
        self.accumulation = &(&self.accumulation * (table, &self.random_coeff)) + evaluation;
    }

    pub fn finalize(self) -> QM31Bar {
        self.accumulation.clone()
    }
}
