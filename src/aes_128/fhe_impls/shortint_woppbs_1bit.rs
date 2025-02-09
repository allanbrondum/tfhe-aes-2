//! Implementation of AES-128 using 1 bit `shortint` WoP-PBS

use crate::aes_128::fhe_sub_pbs::data_model::{BitT, Byte, ByteT};
use crate::aes_128::SBOX;
use crate::tfhe::shortint_woppbs_1bit::*;

use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::util;
use std::sync::OnceLock;
use tfhe::shortint::wopbs::WopbsLUTBase;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = &self.bits().find_first(|_| true).unwrap().context.clone();

        static IDENTITY_LUT: OnceLock<WopbsLUTBase> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| context.generate_lookup_table(1, 1, |bit| bit));

        self.bits_mut().for_each(|bit| {
            let new_bit = context
                .circuit_bootstrap(&[bit], lut)
                .into_iter()
                .next()
                .expect("one bit");
            *bit = context.extract_bit_from_dual_ciphertext(&new_bit);
        });
    }

    fn aes_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<WopbsLUTBase> = OnceLock::new();
        let lut = SBOX_LUT
            .get_or_init(|| context.generate_lookup_table(8, 8, |byte| SBOX[byte as usize]));

        let new_dual_bits = context.circuit_bootstrap(&self.0.each_ref(), &lut);
        let new_bits: [BitCt; 8] = util::par_collect_array(
            new_dual_bits
                .into_par_iter()
                .map(|dual_bit| context.extract_bit_from_dual_ciphertext(&dual_bit)),
        );

        Self(new_bits)
    }
}

impl BitT for BitCt {}

#[cfg(test)]
mod test {
    use crate::aes_128::test_helper;
    use crate::logger;
    use tracing::metadata::LevelFilter;

    #[test]
    fn test_light() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_1bit::test::KEYS.clone();

        test_helper::test_light(client_key.as_ref(), &ctx);
    }

    #[test]
    #[cfg(feature = "long_running_tests")]
    fn test_full() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_1bit::test::KEYS.clone();

        test_helper::test_full(client_key.as_ref(), &ctx);
    }
}
