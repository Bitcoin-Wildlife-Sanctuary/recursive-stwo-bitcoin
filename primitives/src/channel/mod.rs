use crate::cm31::CM31Bar;
use crate::m31::M31Bar;
use crate::qm31::QM31Bar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef;

pub mod sha256;
pub mod utils;

pub trait ChannelBar: Sized {
    type HashType;

    fn default(bs: &BitcoinSystemRef) -> Result<Self>;
    fn new_with_digest(new_digest: &Self::HashType) -> Result<Self>;
    fn update_digest(&mut self, new_digest: &Self::HashType);

    fn draw_digest(&mut self) -> Self::HashType;
    fn draw_m31(&mut self, n: usize) -> Vec<M31Bar>;

    fn mix_root(&mut self, hash: &Self::HashType);

    fn mix_felts(&mut self, v: &[QM31Bar]);

    fn draw_felt(&mut self) -> QM31Bar {
        let m31 = self.draw_m31(4);
        QM31Bar {
            first: CM31Bar {
                imag: m31[1].clone(),
                real: m31[0].clone(),
            },
            second: CM31Bar {
                imag: m31[3].clone(),
                real: m31[2].clone(),
            },
        }
    }

    fn draw_numbers(&mut self, n: usize, logn: usize) -> Vec<M31Bar> {
        let mut m31 = self.draw_m31(n);

        for elem in m31.iter_mut() {
            *elem = elem.trim(logn);
        }

        m31
    }
}
