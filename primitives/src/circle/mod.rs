use crate::fields::m31::M31Bar;
use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use std::ops::{Add, Neg};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

pub mod precomputed;

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

impl Add<(&TableBar, &CirclePoint<M31>)> for &CirclePointQM31Bar {
    type Output = CirclePointQM31Bar;

    fn add(self, rhs: (&TableBar, &CirclePoint<M31>)) -> Self::Output {
        let (table, rhs) = rhs;
        let cs = table.cs().and(&self.x.cs()).and(&self.y.cs());
        let rhs = CirclePointM31Bar::new_constant(&cs, (rhs.x, rhs.y)).unwrap();
        self + (table, &rhs)
    }
}

impl Add<(&TableBar, &CirclePoint<QM31>)> for &CirclePointQM31Bar {
    type Output = CirclePointQM31Bar;

    fn add(self, rhs: (&TableBar, &CirclePoint<QM31>)) -> Self::Output {
        let (table, rhs) = rhs;
        let cs = table.cs().and(&self.x.cs()).and(&self.y.cs());
        let rhs = CirclePointQM31Bar::new_constant(&cs, (rhs.x, rhs.y)).unwrap();
        self + (table, &rhs)
    }
}

impl Add<(&TableBar, &CirclePointQM31Bar)> for &CirclePointQM31Bar {
    type Output = CirclePointQM31Bar;

    fn add(self, rhs: (&TableBar, &CirclePointQM31Bar)) -> Self::Output {
        let (table, rhs) = rhs;

        let x1x2 = &self.x * (table, &rhs.x);
        let y1y2 = &self.y * (table, &rhs.y);
        let x1y2 = &self.x * (table, &rhs.y);
        let y1x2 = &self.y * (table, &rhs.x);

        let new_x = &x1x2 - &y1y2;
        let new_y = &x1y2 + &y1x2;

        CirclePointQM31Bar { x: new_x, y: new_y }
    }
}

impl Add<(&TableBar, &CirclePointM31Bar)> for &CirclePointQM31Bar {
    type Output = CirclePointQM31Bar;

    fn add(self, rhs: (&TableBar, &CirclePointM31Bar)) -> Self::Output {
        let (table, rhs) = rhs;

        let x1x2 = &self.x * (table, &rhs.x);
        let y1y2 = &self.y * (table, &rhs.y);
        let x1y2 = &self.x * (table, &rhs.y);
        let y1x2 = &self.y * (table, &rhs.x);

        let new_x = &x1x2 - &y1y2;
        let new_y = &x1y2 + &y1x2;

        CirclePointQM31Bar { x: new_x, y: new_y }
    }
}

impl CirclePointQM31Bar {
    pub fn from_t(table: &TableBar, t: &QM31Bar) -> Self {
        let t_doubled = t + t;
        let t_squared = t * (table, t);

        let t_squared_plus_1 = t_squared.add1();
        let t_squared_plus_1_inverse = t_squared_plus_1.inverse(table);

        let one_minus_t_squared = t_squared.neg().add1();

        let x = &one_minus_t_squared * (table, &t_squared_plus_1_inverse);
        let y = &t_doubled * (table, &t_squared_plus_1_inverse);

        Self { x, y }
    }
}
