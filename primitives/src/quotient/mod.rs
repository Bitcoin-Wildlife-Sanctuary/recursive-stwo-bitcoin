use crate::circle::CirclePointQM31Bar;
use crate::fields::qm31::QM31Bar;
use crate::fields::table::TableBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::ComplexConjugate;

pub fn complex_conjugate_line_coeffs_var(
    table: &TableBar,
    point: &CirclePointQM31Bar,
    value: &QM31Bar,
    alpha: &QM31Bar,
) -> Result<(QM31Bar, QM31Bar, QM31Bar)> {
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

    Ok((
        alpha * (table, &a),
        alpha * (table, &b),
        alpha * (table, &c),
    ))
}
