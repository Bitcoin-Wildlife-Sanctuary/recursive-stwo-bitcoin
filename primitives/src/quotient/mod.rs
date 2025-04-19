use crate::circle::CirclePointQM31Bar;
use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use serde::{Deserialize, Serialize};
use std::ops::Neg;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::ComplexConjugate;

#[derive(Clone, Serialize, Deserialize)]
pub struct ColumnLineCoeff {
    pub a: QM31,
    pub b: QM31,
    pub c: QM31,
}

#[derive(Clone)]
pub struct ColumnLineCoeffBar {
    pub a: QM31Bar,
    pub b: QM31Bar,
    pub c: QM31Bar,
}

impl Bar for ColumnLineCoeffBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.a.cs().and(&self.b.cs()).and(&self.c.cs())
    }

    fn variables(&self) -> Vec<usize> {
        let mut v = Vec::with_capacity(12);
        v.extend(self.a.variables());
        v.extend(self.b.variables());
        v.extend(self.c.variables());
        v
    }

    fn length() -> usize {
        <QM31Bar as Bar>::length() * 3
    }
}

impl AllocBar for ColumnLineCoeffBar {
    type Value = ColumnLineCoeff;

    fn value(&self) -> Result<Self::Value> {
        Ok(ColumnLineCoeff {
            a: self.a.value()?,
            b: self.b.value()?,
            c: self.c.value()?,
        })
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let a = QM31Bar::new_variable(cs, data.a, mode)?;
        let b = QM31Bar::new_variable(cs, data.b, mode)?;
        let c = QM31Bar::new_variable(cs, data.c, mode)?;
        Ok(Self { a, b, c })
    }
}

pub fn complex_conjugate_line_coeffs_var(
    table: &TableBar,
    point: &CirclePointQM31Bar,
    value: &QM31Bar,
    alpha: &QM31Bar,
) -> Result<ColumnLineCoeffBar> {
    assert_ne!(
        point.y.value()?,
        point.y.value()?.complex_conjugate(),
        "Cannot evaluate a line with a single point ({:?}).",
        CirclePoint {
            x: point.x.value()?,
            y: point.y.value()?
        }
    );

    let value0 = value.first.clone();
    let value1 = value.second.clone();

    let y0 = point.y.first.clone();
    let y1 = point.y.second.clone();

    let b = &(&value0 * (table, &y1)) - &(&value1 * (table, &y0));
    let a = value1;
    let c = y1;

    Ok(ColumnLineCoeffBar {
        a: alpha * (table, &a),
        b: alpha * (table, &b),
        c: alpha * (table, &c),
    })
}

#[derive(Clone)]
pub struct LineCoeffRandomizerBar {
    pub alpha: QM31Bar,
}

impl Bar for LineCoeffRandomizerBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.alpha.cs()
    }

    fn variables(&self) -> Vec<usize> {
        self.alpha.variables()
    }

    fn length() -> usize {
        <QM31Bar as Bar>::length()
    }
}

impl AllocBar for LineCoeffRandomizerBar {
    type Value = QM31;

    fn value(&self) -> Result<Self::Value> {
        self.alpha.value()
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let alpha = QM31Bar::new_variable(cs, data, mode)?;
        Ok(Self { alpha })
    }
}

impl LineCoeffRandomizerBar {
    pub fn new(cs: &BitcoinSystemRef, after_sampled_values_random_coeff: &QM31Bar) -> Result<Self> {
        let alpha = after_sampled_values_random_coeff
            * &QM31Bar::new_constant(
                &cs,
                QM31::from_m31(M31::zero(), M31::zero(), M31::from(2).neg(), M31::zero()),
            )?;
        Ok(Self { alpha })
    }

    pub fn get_and_update(
        &mut self,
        table: &TableBar,
        after_sampled_values_random_coeff: &QM31Bar,
    ) -> QM31Bar {
        let res = self.alpha.clone();
        self.alpha = &self.alpha * (table, after_sampled_values_random_coeff);
        res
    }
}
