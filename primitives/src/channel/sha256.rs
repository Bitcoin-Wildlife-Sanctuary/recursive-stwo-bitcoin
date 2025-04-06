use crate::channel::utils::reconstruct_for_channel_draw;
use crate::channel::ChannelBar;
use crate::fields::m31::M31Bar;
use crate::fields::qm31::QM31Bar;
use crate::utils::{hash, hash_qm31_gadget};
use anyhow::Result;
use bitcoin::script::write_scriptint;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, AllocationMode, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;
use serde::{Deserialize, Serialize};
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::vcs::bitcoin_num_to_bytes;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

#[derive(Clone)]
pub struct Sha256ChannelBar {
    pub digest: Sha256HashBar,
    pub n_challenges: usize,
    pub n_sent: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Sha256ChannelValue {
    pub digest: Sha256Hash,
    pub n_challenges: usize,
    pub n_sent: usize,
}

impl Bar for Sha256ChannelBar {
    fn cs(&self) -> BitcoinSystemRef {
        self.digest.cs()
    }

    fn variables(&self) -> Vec<usize> {
        vec![self.digest.variable]
    }

    fn length() -> usize {
        1
    }
}

impl AllocBar for Sha256ChannelBar {
    type Value = Sha256ChannelValue;

    fn value(&self) -> Result<Self::Value> {
        Ok(Sha256ChannelValue {
            digest: self.digest.value,
            n_challenges: self.n_challenges,
            n_sent: self.n_sent,
        })
    }

    fn new_variable(
        cs: &BitcoinSystemRef,
        data: Self::Value,
        mode: AllocationMode,
    ) -> Result<Self> {
        let digest = Sha256HashBar::new_variable(cs, data.digest, mode)?;
        Ok(Self {
            digest,
            n_challenges: data.n_challenges,
            n_sent: data.n_sent,
        })
    }
}

impl ChannelBar for Sha256ChannelBar {
    type HashType = Sha256HashBar;

    fn default(cs: &BitcoinSystemRef) -> Result<Self> {
        let digest = Sha256HashBar::new_constant(&cs, Sha256Hash::default().into())?;
        let n_challenges = 0;
        let n_sent = 0;

        Ok(Self {
            digest,
            n_challenges,
            n_sent,
        })
    }

    fn new_with_digest(new_digest: &Self::HashType) -> Result<Self> {
        let digest = new_digest.clone();
        let n_challenges = 1;
        let n_sent = 0;

        Ok(Self {
            digest,
            n_challenges,
            n_sent,
        })
    }

    fn update_digest(&mut self, new_digest: &Self::HashType) {
        self.digest = new_digest.clone();
        self.n_challenges += 1;
        self.n_sent = 0;
    }

    fn draw_digest(&mut self) -> Sha256HashBar {
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, self.digest.value.as_ref());
        Update::update(&mut sha256, &self.n_sent.to_le_bytes());
        let drawn_digest = sha256.finalize().to_vec();

        let cs = self.digest.cs();
        cs.insert_script_complex(
            draw_digest_gadget,
            vec![self.digest.variable],
            &Options::new().with_u32("n_sent", self.n_sent as u32),
        )
        .unwrap();

        self.n_sent += 1;
        Sha256HashBar::new_function_output(&cs, drawn_digest.into()).unwrap()
    }

    fn draw_m31(&mut self, mut n: usize) -> Vec<M31Bar> {
        let mut all_m31 = vec![];

        while n > 0 {
            let m = core::cmp::min(n, 8);

            let to_extract = self.draw_digest();
            all_m31.extend(unpack_multi_m31(m, &to_extract));

            n -= m;
        }

        all_m31
    }

    fn mix_root(&mut self, hash: &Self::HashType) {
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, self.digest.value.as_ref());
        Update::update(&mut sha256, hash.value.as_ref());
        let new_digest = sha256.finalize().to_vec();

        let cs = self.digest.cs();
        cs.insert_script(mix_root_gadget, vec![self.digest.variable, hash.variable])
            .unwrap();
        self.update_digest(&Sha256HashBar::new_function_output(&cs, new_digest.into()).unwrap());
    }

    fn mix_felts(&mut self, felts: &[QM31Bar]) {
        for felt in felts.iter() {
            let mut sha256 = Sha256::new();
            Digest::update(&mut sha256, sha256_qm31(&felt.value().unwrap()));
            Digest::update(&mut sha256, self.digest.value);
            let drawn_digest = sha256.finalize().to_vec();

            let cs = self.digest.cs();
            cs.insert_script(
                mix_felt_gadget,
                vec![
                    felt.second.imag.variable,
                    felt.second.real.variable,
                    felt.first.imag.variable,
                    felt.first.real.variable,
                    self.digest.variable,
                ],
            )
            .unwrap();
            self.update_digest(
                &Sha256HashBar::new_function_output(&cs, drawn_digest.into()).unwrap(),
            );
        }
    }

    fn mix_str(&mut self, value: &StrBar) {
        assert_eq!(value.value.len(), 32);
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, &value.value);
        Digest::update(&mut sha256, self.digest.value);
        let new_digest = sha256.finalize().to_vec();

        let cs = self.digest.cs();
        cs.insert_script(mix_str_gadget, vec![value.variable, self.digest.variable])
            .unwrap();
        self.update_digest(&Sha256HashBar::new_function_output(&cs, new_digest.into()).unwrap());
    }
}

fn mix_str_gadget() -> Script {
    script! {
        OP_CAT hash
    }
}

fn mix_felt_gadget() -> Script {
    script! {
        OP_TOALTSTACK
        hash_qm31_gadget
        OP_FROMALTSTACK OP_CAT hash
    }
}

fn sha256_qm31(v: &QM31) -> [u8; 32] {
    let mut res = [0u8; 32];

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, bitcoin_num_to_bytes(v.0 .0));
    res.copy_from_slice(hasher.finalize().as_slice());

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, bitcoin_num_to_bytes(v.0 .1));
    Digest::update(&mut hasher, res);
    res.copy_from_slice(hasher.finalize().as_slice());

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, bitcoin_num_to_bytes(v.1 .0));
    Digest::update(&mut hasher, res);
    res.copy_from_slice(hasher.finalize().as_slice());

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, bitcoin_num_to_bytes(v.1 .1));
    Digest::update(&mut hasher, res);
    res.copy_from_slice(hasher.finalize().as_slice());

    res
}

fn unpack_multi_m31(m: usize, to_extract: &Sha256HashBar) -> Vec<M31Bar> {
    assert!(m <= 8);

    let cs = to_extract.cs();
    let value = to_extract.value.as_ref();

    let mut m31_values = Vec::with_capacity(m);
    let mut hint_values = Vec::with_capacity(m);

    for i in 0..m {
        let res = u32::from_le_bytes(<[u8; 4]>::try_from(&value[i * 4..(i + 1) * 4]).unwrap())
            & 0x7fffffff;

        hint_values.push(if value[(i + 1) * 4 - 1] & 0x80 != 0 {
            if res == 0 {
                vec![0x80]
            } else {
                let mut out = [0u8; 8];
                let len = write_scriptint(&mut out, (res as i64).neg());
                out[0..len].to_vec()
            }
        } else {
            let mut out = [0u8; 8];
            let len = write_scriptint(&mut out, res as i64);
            out[0..len].to_vec()
        });
        m31_values.push(M31::from(res));
    }

    let mut m31 = vec![];
    let mut str = Option::<StrBar>::None;

    for v in hint_values.iter() {
        let hint = StrBar::new_hint(&cs, v.clone()).unwrap();
        let (this_m31, this_str) = reconstruct_for_channel_draw(&hint);
        m31.push(this_m31);

        if let Some(v) = &str {
            str = Some(v + &this_str);
        } else {
            str = Some(this_str);
        }
    }

    let mut str = str.unwrap();
    if m != 8 {
        str = &str + &StrBar::new_hint(&cs, value[4 * m..].to_vec()).unwrap();
    }
    StrBar::from(to_extract).equalverify(&str).unwrap();

    m31
}

fn draw_digest_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    Ok(script! {
        { (options.get_u32("n_sent")? as usize).to_le_bytes().to_vec() } OP_CAT hash
    })
}

fn mix_root_gadget() -> Script {
    script! {
        OP_CAT hash
    }
}

#[cfg(test)]
mod test {
    use crate::channel::sha256::Sha256ChannelBar;
    use crate::channel::ChannelBar;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use recursive_stwo_bitcoin_dsl::bar::AllocBar;
    use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
    use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;
    use recursive_stwo_bitcoin_dsl::test_program;
    use recursive_stwo_bitcoin_dsl::treepp::*;
    use stwo_prover::core::channel::{Channel, Sha256Channel};
    use stwo_prover::core::queries::UPPER_BOUND_QUERY_BYTES;
    use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

    #[test]
    fn test_draw_felt() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());
        let init_state = Sha256Hash::from(init_state.to_vec());

        let mut channel = Sha256Channel::default();
        channel.update_digest(init_state);
        let b = channel.draw_felt();
        let c = channel.digest();

        let cs = BitcoinSystemRef::new_ref();

        let mut channel_var = Sha256ChannelBar::new_with_digest(
            &Sha256HashBar::new_constant(&cs, init_state.as_ref().to_vec().into()).unwrap(),
        )
        .unwrap();
        let res = channel_var.draw_felt();

        cs.set_program_output(&channel_var.digest).unwrap();
        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                { c }
                { b }
            },
        )
        .unwrap();
    }

    #[test]
    fn test_draw_numbers() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());
        let init_state = Sha256Hash::from(init_state.to_vec());

        let mut channel = Sha256Channel::default();
        channel.update_digest(init_state);

        let mut queries = vec![];
        while queries.len() < 8 {
            for chunk in channel
                .draw_random_bytes()
                .chunks_exact(UPPER_BOUND_QUERY_BYTES)
            {
                queries.push(u32::from_le_bytes(chunk.try_into().unwrap()) & ((1 << 12) - 1));
            }
        }

        let cs = BitcoinSystemRef::new_ref();

        let mut channel_var = Sha256ChannelBar::new_with_digest(
            &Sha256HashBar::new_constant(&cs, init_state.as_ref().to_vec().into()).unwrap(),
        )
        .unwrap();
        let res = channel_var.draw_numbers(8, 12);

        cs.set_program_output(&channel_var.digest).unwrap();
        for elem in res.iter() {
            cs.set_program_output(elem).unwrap();
        }

        test_program(
            cs,
            script! {
                { channel.digest().as_ref().to_vec() }
                for number in queries {
                    { number }
                }
            },
        )
        .unwrap();
    }
}
