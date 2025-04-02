use crate::fields::m31::M31Bar;
use crate::fields::qm31::QM31Bar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
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
    fn mix_str(&mut self, value: &StrBar);

    fn draw_felt(&mut self) -> QM31Bar {
        let m31 = self.draw_m31(4);
        QM31Bar::from_m31(&m31[0], &m31[1], &m31[2], &m31[3])
    }

    fn draw_felts(&mut self) -> [QM31Bar; 2] {
        let m31 = self.draw_m31(8);
        let a = QM31Bar::from_m31(&m31[0], &m31[1], &m31[2], &m31[3]);
        let b = QM31Bar::from_m31(&m31[4], &m31[5], &m31[6], &m31[7]);
        [a, b]
    }

    fn draw_numbers(&mut self, n: usize, logn: usize) -> Vec<M31Bar> {
        let mut m31 = self.draw_m31(n);

        for elem in m31.iter_mut() {
            *elem = elem.trim(logn);
        }

        m31
    }
}
