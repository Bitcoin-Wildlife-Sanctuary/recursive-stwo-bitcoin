//! PlonkWithPoseidon Per-Query Part 5: Poseidon Trace Numerators
//!
//! This script computes numerators for Poseidon trace columns (48 columns).
//! The column values were stored by part4.
//!
//! Poseidon trace columns (48):
//! - in_state[16]: input state
//! - intermediate[16]: intermediate state after partial round
//! - out_state[16]: output state

use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use num_traits::Zero;
use stwo_prover::core::fields::qm31::QM31;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::quotient::ColumnLineCoeffBar;

pub fn generate_cs(
    ldm: &mut LDM,
    ldm_per_query: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;
    ldm_per_query.init(&cs)?;

    let table = TableBar::new_constant(&cs, ())?;
    let point_24_y: M31Bar = ldm_per_query.read("point_24_y")?;

    let mut numerator_poseidon_trace = QM31Bar::new_constant(&cs, QM31::zero())?;

    // in_state columns (0-15)
    for i in 0..16 {
        let label = format!("poseidon_trace_in_state_{}", i);
        let val: M31Bar = ldm_per_query.read(format!("poseidon_trace_val_{}", i))?;
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &val);
        numerator_poseidon_trace = &numerator_poseidon_trace + &numerator;
    }

    // intermediate columns (16-31)
    for i in 0..16 {
        let label = format!("poseidon_trace_intermediate_{}", i);
        let val: M31Bar = ldm_per_query.read(format!("poseidon_trace_val_{}", 16 + i))?;
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &val);
        numerator_poseidon_trace = &numerator_poseidon_trace + &numerator;
    }

    // out_state columns (32-47)
    for i in 0..16 {
        let label = format!("poseidon_trace_out_state_{}", i);
        let val: M31Bar = ldm_per_query.read(format!("poseidon_trace_val_{}", 32 + i))?;
        let line_coeff: ColumnLineCoeffBar = ldm.read(format!("column_line_coeff_{}", label))?;
        let numerator = line_coeff.apply(&table, &point_24_y, &val);
        numerator_poseidon_trace = &numerator_poseidon_trace + &numerator;
    }

    // Combine with PLONK trace numerator
    let numerator_plonk_trace: QM31Bar = ldm_per_query.read("numerator_plonk_trace")?;
    let numerator_trace = &numerator_plonk_trace + &numerator_poseidon_trace;

    ldm_per_query.write("numerator_trace", &numerator_trace)?;

    ldm.save()?;
    ldm_per_query.save()?;
    Ok(cs)
}
