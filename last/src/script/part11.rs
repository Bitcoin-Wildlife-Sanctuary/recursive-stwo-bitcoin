use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::ldm::LDM;
use recursive_stwo_primitives::composition::PointEvaluationAccumulatorBar;
use recursive_stwo_primitives::fields::m31::M31Bar;
use recursive_stwo_primitives::fields::qm31::QM31Bar;
use recursive_stwo_primitives::fields::table::TableBar;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;
use stwo_prover::examples::plonk_without_poseidon::air::PlonkWithoutPoseidonProof;

pub fn generate_cs(
    proof: &PlonkWithoutPoseidonProof<Sha256MerkleHasher>,
    ldm: &mut LDM,
) -> Result<BitcoinSystemRef> {
    let cs = BitcoinSystemRef::new_ref();
    ldm.init(&cs)?;

    let interaction_prev: QM31Bar = ldm.read("interaction_prev")?;
    let interaction: QM31Bar = ldm.read("interaction")?;
    let diff = &interaction - &interaction_prev;

    let plonk_total_sum: QM31Bar = ldm.read("plonk_total_sum")?;
    let shift = M31::from_u32_unchecked(1 << proof.stmt0.log_size_plonk).inverse();

    let table = TableBar::new_constant(&cs, ())?;
    let cumsum_shift: QM31Bar = &plonk_total_sum * (&table, &M31Bar::new_constant(&cs, shift)?);
    let fixed_diff = &diff + &cumsum_shift;

    let relation_num: QM31Bar = ldm.read("relation_num")?;
    let relation_denom: QM31Bar = ldm.read("relation_denom")?;

    let random_coeff: QM31Bar = ldm.read("random_coeff")?;
    let accumulation: QM31Bar = ldm.read("eval_acc_accumulation_part6")?;

    let mut eval_acc = PointEvaluationAccumulatorBar {
        random_coeff,
        accumulation,
    };

    eval_acc.accumulate(
        &table,
        &(&(&fixed_diff * (&table, &relation_denom)) - &relation_num),
    );

    let coset_vanishing_x_inv: QM31Bar = ldm.read("coset_vanishing_x_inv")?;
    let expected_composition = &eval_acc.accumulation * (&table, &coset_vanishing_x_inv);

    let composition: QM31Bar = ldm.read("composition")?;
    composition.equalverify(&expected_composition)?;

    ldm.save()?;
    Ok(cs)
}
