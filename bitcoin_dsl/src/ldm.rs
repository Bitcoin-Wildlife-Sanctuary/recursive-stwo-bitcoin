use crate::bar::{AllocBar, Bar};
use crate::basic::sha256_hash::Sha256HashBar;
use crate::bitcoin_system::BitcoinSystemRef;
use anyhow::Result;
use serde::de::DeserializeOwned;
use sha2::Digest;
use std::collections::HashMap;

#[derive(Default)]
pub struct LDM {
    pub name_to_id: HashMap<String, usize>,
    pub value_map: Vec<Vec<u8>>,
    pub hash_map: Vec<Vec<u8>>,

    pub cs: Option<BitcoinSystemRef>,
    pub hash_var: Option<Sha256HashBar>,
    pub log: Vec<usize>,
}

impl LDM {
    pub fn new() -> LDM {
        Self::default()
    }

    pub fn init(&mut self, cs: &BitcoinSystemRef) -> Result<()> {
        if self.cs.is_some() {
            let read_hash = self.hash_var.as_ref().unwrap().value.clone();
            self.cs = Some(cs.clone());
            self.hash_var = Some(Sha256HashBar::new_program_input(&cs, read_hash)?);
        } else {
            self.cs = Some(cs.clone());
            let default_hash = sha2::Sha256::digest(b"ldm").to_vec();
            let hash_var = Sha256HashBar::new_constant(&cs, default_hash.into())?;
            self.hash_var = Some(hash_var);
        }

        Ok(())
    }

    pub fn write<T: Bar + AllocBar>(&mut self, name: impl ToString, value: &T) -> Result<()> {
        assert!(
            self.cs.is_some(),
            "The WORMMemory is not bound to a constraint system."
        );

        let idx = self.value_map.len();
        self.name_to_id.insert(name.to_string(), idx);

        self.value_map.push(bincode::serialize(&value.value()?)?);

        let hash_var = Sha256HashBar::from(value);
        self.hash_map.push(hash_var.value.into());

        self.hash_var = Some(self.hash_var.as_ref().unwrap() + &hash_var);
        self.log.push(idx);

        Ok(())
    }

    pub fn read<T: Bar + AllocBar>(&mut self, name: impl ToString) -> Result<T> {
        let idx = self.name_to_id[&name.to_string()];

        let value: T::Value = bincode::deserialize(&self.value_map[idx])?;
        let v = T::new_hint(self.cs.as_ref().unwrap(), value)?;

        self.hash_var = Some(self.hash_var.as_ref().unwrap() + &Sha256HashBar::from(&v));
        self.log.push(idx);

        Ok(v)
    }

    pub fn debug_read<T: DeserializeOwned>(&mut self, name: impl ToString) -> Result<T> {
        let idx = self.name_to_id[&name.to_string()];
        Ok(bincode::deserialize(&self.value_map[idx])?)
    }

    pub fn save(&self) -> Result<()> {
        self.cs
            .as_ref()
            .unwrap()
            .set_program_output(self.hash_var.as_ref().unwrap())?;
        Ok(())
    }

    pub fn check(&self) -> Result<()> {
        let mut next_index_to_load = 0;
        let mut map = Vec::<Sha256HashBar>::new();
        let cs = self.cs.as_ref().unwrap();

        let default_hash = sha2::Sha256::digest(b"ldm").to_vec();
        let mut recomputed_hash_var = Sha256HashBar::new_constant(&cs, default_hash.into())?;

        let mut log_iter = self.log.iter().peekable();

        while next_index_to_load < self.value_map.len() {
            // load the next value
            let new_hash_var =
                Sha256HashBar::new_hint(cs, self.hash_map[next_index_to_load].clone().into())?;
            next_index_to_load += 1;
            map.push(new_hash_var);

            // peek the next read_log element
            let mut next = log_iter.peek();
            while next.is_some() && **next.unwrap() < next_index_to_load {
                let id = *log_iter.next().unwrap();
                recomputed_hash_var = &recomputed_hash_var + &map[id];
                next = log_iter.peek();
            }
        }

        self.hash_var
            .as_ref()
            .unwrap()
            .equalverify(&recomputed_hash_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::bar::AllocBar;
    use crate::basic::sha256_hash::Sha256HashBar;
    use crate::bitcoin_system::BitcoinSystemRef;
    use crate::ldm::LDM;
    use crate::test_program;
    use crate::treepp::*;
    use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ldm() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val: [u8; 32] = prng.gen();
        let b_val: [u8; 32] = prng.gen();

        let mut ldm = LDM::new();

        let cs = BitcoinSystemRef::new_ref();
        ldm.init(&cs).unwrap();

        let a = Sha256HashBar::new_constant(&cs, a_val.to_vec().into()).unwrap();
        let b = Sha256HashBar::new_constant(&cs, b_val.to_vec().into()).unwrap();

        let c = &a + &b;
        let c_val = c.value().unwrap();

        ldm.write("c", &c).unwrap();
        ldm.save().unwrap();

        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = BitcoinSystemRef::new_ref();
        ldm.init(&cs).unwrap();

        let c = ldm.read::<Sha256HashBar>("c").unwrap();
        assert_eq!(c.value().unwrap(), c_val);

        ldm.check().unwrap();
        ldm.save().unwrap();

        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();
    }
}
