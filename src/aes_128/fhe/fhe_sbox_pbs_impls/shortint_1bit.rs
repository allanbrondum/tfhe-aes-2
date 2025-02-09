//! Implementation of AES-128 using 1 bit `shortint`

use crate::aes_128::fhe::data_model::Byte;
use std::array;

use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::aes_128::fhe::data_model::BitT;
use crate::aes_128::fhe::fhe_sbox_pbs::ByteT;
use crate::aes_128::SBOX;
use crate::tfhe::shortint_1bit;
use crate::tfhe::shortint_1bit::{BitCt, MultivariateTestVector, TestVector};
use crate::util;
use std::sync::OnceLock;
use tfhe::core_crypto::entities::Cleartext;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = self.0[0].context.clone();

        static IDENTITY_LUT: OnceLock<TestVector> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| context.test_vector_from_cleartext_fn(|byte| byte));

        self.bits_mut().for_each(|bit| {
            context.bootstrap_assign(bit, lut);
        });
    }

    fn sbox_substitute(&self) -> Self {
        let context = &self.0[0].context;

        static SBOX_LUT: OnceLock<[MultivariateTestVector; 8]> = OnceLock::new();
        let lut = SBOX_LUT.get_or_init(|| {
            array::from_fn(|i| {
                shortint_1bit::generate_multivariate_test_vector(context, 8, |byte| {
                    Cleartext(util::byte_to_bits(SBOX[byte as usize])[i] as u64)
                })
            })
        });

        let new_bits = util::par_collect_array((0..8).into_par_iter().map(|i| {
            shortint_1bit::calculate_multivariate_function(context, &self.0.each_ref(), &lut[i])
        }));

        Byte::new(new_bits)
    }
}

impl BitT for BitCt {}

#[cfg(test)]
mod test {
    use crate::aes_128::test_helper;
    use crate::logger;
    use tracing::metadata::LevelFilter;

    // tests fail currently due to too big noise accumulation

    #[ignore]
    #[test]
    fn test_light() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_1bit::test::KEYS.clone();

        test_helper::test_light(client_key.as_ref(), &ctx);
    }

    #[ignore]
    #[cfg(feature = "long_running_tests")]
    #[test]
    fn test_full() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_1bit::test::KEYS.clone();

        test_helper::test_full(client_key.as_ref(), &ctx);
    }
}
