use crate::fields::m31::M31Bar;
use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use std::ops::Neg;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

#[derive(Clone, Debug)]
pub struct CirclePointM31Bar {
    pub x: M31Bar,
    pub y: M31Bar,
}

impl AllocBar for CirclePointM31Bar {
    type Value = (M31, M31);

    fn value(&self) -> Result<Self::Value> {
        Ok((self.x.value, self.y.value))
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let x = M31Bar::new_variable(cs, data.0, mode)?;
        let y = M31Bar::new_variable(cs, data.1, mode)?;
        Ok(CirclePointM31Bar { x, y })
    }
}

#[derive(Clone)]
pub struct CirclePointQM31Bar {
    pub x: QM31Bar,
    pub y: QM31Bar,
}

impl AllocBar for CirclePointQM31Bar {
    type Value = (QM31, QM31);

    fn value(&self) -> Result<Self::Value> {
        Ok((self.x.value()?, self.y.value()?))
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let x = QM31Bar::new_variable(cs, data.0, mode)?;
        let y = QM31Bar::new_variable(cs, data.1, mode)?;
        Ok(CirclePointQM31Bar { x, y })
    }
}

impl CirclePointQM31Bar {
    pub fn from_t(table: &TableBar, t: &QM31Bar) -> Self {
        let t_doubled = t + t;
        let t_squared = t * t;

        let t_squared_plus_1 = t_squared.add1();
        let t_squared_plus_1_inverse = t_squared_plus_1.inverse(table);

        let one_minus_t_squared_minus = t_squared.neg().add1();

        let x = &one_minus_t_squared_minus * &t_squared_plus_1_inverse;
        let y = &t_doubled * &t_squared_plus_1_inverse;

        Self { x, y }
    }
}
