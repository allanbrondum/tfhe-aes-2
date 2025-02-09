//! Implementation of AES-128 using 1 bit `shortint` WoP-PBS

use crate::aes_128::fhe::data_model::{BitT, Byte, ByteT};
use crate::aes_128::SBOX;
use crate::tfhe::shortint_woppbs_1bit::*;
use std::array;

use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::util;
use std::sync::OnceLock;
use tfhe::core_crypto::entities::Cleartext;
use tfhe::shortint::wopbs::ShortintWopbsLUT;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = &self.bits().find_first(|_| true).unwrap().context.clone();

        static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| {
            context.generate_multivariate_lookup_table(1, |bit| Cleartext(bit as u64))
        });

        self.bits_mut().for_each(|bit| {
            let new_bit = context.bootstrap_from_bits(&[bit], lut);
            *bit = context.extract_bit_from_bit(&new_bit);
        });
    }

    fn aes_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<[ShortintWopbsLUT; 8]> = OnceLock::new();
        let lut = SBOX_LUT.get_or_init(|| {
            array::from_fn(|i| {
                context.generate_multivariate_lookup_table(8, |byte| {
                    Cleartext(util::byte_to_bits(SBOX[byte as usize])[i] as u64)
                })
            })
        });

        let new_bits = util::par_collect_array((0..8).into_par_iter().map(|i| {
            let new_bit = context.bootstrap_from_bits(&self.0.each_ref(), &lut[i]);
            context.extract_bit_from_bit(&new_bit)
        }));

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
