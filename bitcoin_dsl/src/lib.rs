use crate::bitcoin_system::BitcoinSystemRef;
use crate::compiler::Compiler;
use crate::treepp::pushable::{Builder, Pushable};
use crate::treepp::*;
use anyhow::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::{TapLeafHash, Transaction};
use bitcoin_scriptexec::{convert_to_witness, Exec, ExecCtx, FmtStack, Options, TxTemplate};
use rand::{Rng, RngCore};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

pub mod bar;

pub mod bitcoin_system;

pub mod script_generator;

pub mod options;

pub mod stack;

pub mod basic;

pub mod compiler;

#[allow(missing_docs)]
pub mod treepp {
    pub use bitcoin_script::{define_pushable, script};

    pub use bitcoin_scriptexec::{convert_to_witness, get_final_stack};

    #[cfg(test)]
    pub use bitcoin_scriptexec::{execute_script, execute_script_with_witness_unlimited_stack};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

impl Pushable for M31 {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.1.bitcoin_script_push(builder);
        builder = self.0.bitcoin_script_push(builder);
        builder
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        let mut builder = self.1 .1.bitcoin_script_push(builder);
        builder = self.1 .0.bitcoin_script_push(builder);
        builder = self.0 .1.bitcoin_script_push(builder);
        self.0 .0.bitcoin_script_push(builder)
    }
}

impl Pushable for Sha256Hash {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.as_ref().to_vec().bitcoin_script_push(builder)
    }
}

impl Pushable for CirclePoint<QM31> {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.x.bitcoin_script_push(builder);
        builder = self.y.bitcoin_script_push(builder);
        builder
    }
}

pub fn test_program(cs: BitcoinSystemRef, expected_stack: Script) -> Result<()> {
    test_program_generic(cs, expected_stack, true)
}

pub fn test_program_without_opcat(cs: BitcoinSystemRef, expected_stack: Script) -> Result<()> {
    test_program_generic(cs, expected_stack, false)
}

fn test_program_generic(cs: BitcoinSystemRef, expected_stack: Script, opcat: bool) -> Result<()> {
    let program = Compiler::compile(cs)?;

    let mut script = script! {
        for elem in program.hint.iter() {
            { elem }
        }
        for elem in program.input.iter() {
            { elem }
        }
    }
    .to_bytes();
    script.extend_from_slice(program.script.as_bytes());

    let expected_final_stack = convert_to_witness(expected_stack)
        .map_err(|x| anyhow::Error::msg(format!("final stack parsing error: {:?}", x)))?;
    for elem in expected_final_stack.iter().rev() {
        script.extend_from_slice(
            script! {
                { elem.to_vec() }
                OP_EQUALVERIFY
            }
            .as_bytes(),
        );
    }

    script.push(OP_TRUE.to_u8());

    let script = Script::from_bytes(script);

    println!("script size: {}", script.len());

    let mut options = Options::default();
    if !opcat {
        options.experimental.op_cat = false;
    };

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        options,
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    if !res.success {
        println!("{:8}", FmtStack(exec.stack().clone()));
        println!("{:?}", res.error);
    }

    println!("max stack size: {}", exec.stats().max_nb_stack_items);

    if res.success {
        Ok(())
    } else {
        Err(Error::msg("Script execution is not successful"))
    }
}

pub fn rand_m31<R: RngCore>(prng: &mut R) -> M31 {
    M31::from_u32_unchecked(prng.gen_range(0..((1i64 << 31) - 1)) as u32)
}

pub fn rand_cm31<R: RngCore>(prng: &mut R) -> CM31 {
    CM31::from_m31(rand_m31(prng), rand_m31(prng))
}

pub fn rand_qm31<R: RngCore>(prng: &mut R) -> QM31 {
    QM31::from_m31(
        rand_m31(prng),
        rand_m31(prng),
        rand_m31(prng),
        rand_m31(prng),
    )
}

#[cfg(test)]
mod test {
    use crate::rand_qm31;
    use crate::treepp::{
        pushable::{Builder, Pushable},
        *,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_pushable() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let m31 = M31::reduce(prng.next_u64());
        let cm31 = CM31::from_m31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64()));
        let qm31 = rand_qm31(&mut prng);

        let mut builder = Builder::new();
        builder = m31.bitcoin_script_push(builder);
        assert_eq!(script! { {m31} }.as_bytes(), builder.as_bytes());

        let mut builder = Builder::new();
        builder = cm31.bitcoin_script_push(builder);
        assert_eq!(script! { {cm31} }.as_bytes(), builder.as_bytes());

        let mut builder = Builder::new();
        builder = qm31.bitcoin_script_push(builder);
        assert_eq!(script! { {qm31} }.as_bytes(), builder.as_bytes());
    }
}
