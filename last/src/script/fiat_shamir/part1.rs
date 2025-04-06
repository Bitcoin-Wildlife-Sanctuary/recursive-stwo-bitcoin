use anyhow::Result;
use num_traits::One;
use recursive_stwo_bitcoin_dsl::bar::AllocBar;
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::channel::sha256::Sha256ChannelBar;
use recursive_stwo_primitives::channel::ChannelBar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use recursive_stwo_primitives::input_sum::InputSumBar;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let mut channel_var = Sha256ChannelBar::default(&cs)?;

    // Preprocessed trace.
    let preprocessed_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[0].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&preprocessed_commitment_var);

    // Update the channel with the log sizes
    let mut d = [0u8; 32];
    d[0..4].copy_from_slice(&proof.stmt0.log_size_plonk.to_le_bytes());
    channel_var.mix_str(&StrBar::new_constant(&cs, d.to_vec())?);

    // Trace.
    let trace_commitment_var = Sha256HashBar::new_hint(
        &cs,
        proof.stark_proof.commitments[1].as_ref().to_vec().into(),
    )?;
    channel_var.mix_root(&trace_commitment_var);

    // Draw interaction elements (specifically, z and alpha)
    let [z, alpha] = channel_var.draw_felts();
    ldm.write("z", &z)?;
    ldm.write("alpha", &alpha)?;

    ldm.write("channel_var_after_z_and_alpha", &channel_var)?;

    let mut input_acc = InputSumBar::new(&z, &alpha)?;
    let table = TableBar::new_constant(&cs, ())?;

    input_acc.accumulate(&table, &QM31Bar::new_constant(&cs, QM31::one())?);
    input_acc.accumulate(
        &table,
        &QM31Bar::new_constant(&cs, QM31::from_u32_unchecked(0, 1, 0, 0))?,
    );
    input_acc.accumulate(
        &table,
        &QM31Bar::new_constant(&cs, QM31::from_u32_unchecked(0, 0, 1, 0))?,
    );

    ldm.write("input_acc_alpha_0", &input_acc.alpha)?;
    ldm.write("input_acc_cur_0", &input_acc.cur)?;
    ldm.write("input_acc_sum_0", &input_acc.sum)?;

    ldm.save()?;
    Ok(cs)
}
