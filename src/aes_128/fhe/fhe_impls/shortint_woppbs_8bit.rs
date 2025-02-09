//! Implementation of AES-128 using 8 bit `shortint` WoP-PBS

use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::SBOX;
use crate::tfhe::shortint_woppbs_8bit::*;

use rayon::iter::ParallelIterator;

use std::sync::OnceLock;

use crate::aes_128::fhe::fhe_sbox_pbs::ByteT;
use crate::aes_128::fhe::{fhe_sbox_pbs, Aes128Encrypt};
use crate::tfhe::ContextT;
use tfhe::shortint::wopbs::ShortintWopbsLUT;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| context.generate_lookup_table(|byte| byte));

        *self = self.bootstrap_with_lut(context, lut);
    }

    fn sbox_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = SBOX_LUT
            .get_or_init(|| context.generate_lookup_table(|byte| SBOX[byte as usize].into()));

        self.bootstrap_with_lut(context, lut)
    }
}

impl Byte<BitCt> {
    fn bootstrap_with_lut(&self, context: &FheContext, lut: &ShortintWopbsLUT) -> Self {
        let int_byte = context.bootstrap_from_bits(self, lut);
        context.extract_bits_from_ciphertext(&int_byte)
    }
}

pub struct ShortintWoppbs8BitSboxPbsAesEncrypt;

impl Aes128Encrypt for ShortintWoppbs8BitSboxPbsAesEncrypt {
    type Ctx = FheContext;

    fn encrypt_block_for_rounds(
        ctx: &Self::Ctx,
        expanded_key: &[Word<<Self::Ctx as ContextT>::Bit>; 44],
        block: Block<<Self::Ctx as ContextT>::Bit>,
        rounds: usize,
    ) -> Block<<Self::Ctx as ContextT>::Bit> {
        fhe_sbox_pbs::encrypt_block_for_rounds(ctx, expanded_key, block, rounds)
    }

    fn key_schedule(
        ctx: &Self::Ctx,
        key_slice: &[Byte<<Self::Ctx as ContextT>::Bit>; 16],
    ) -> [Word<<Self::Ctx as ContextT>::Bit>; 44] {
        fhe_sbox_pbs::key_schedule(ctx, key_slice)
    }
}

#[cfg(test)]
mod test {
    use crate::aes_128::fhe::fhe_impls::shortint_woppbs_8bit::ShortintWoppbs8BitSboxPbsAesEncrypt;
    use crate::aes_128::test_helper;
    use crate::logger;
    use tracing::metadata::LevelFilter;

    #[test]
    fn test_light() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_8bit::test::KEYS.clone();

        test_helper::test_light::<ShortintWoppbs8BitSboxPbsAesEncrypt, _>(
            client_key.as_ref(),
            &ctx,
        );
    }

    #[test]
    #[cfg(feature = "long_running_tests")]
    fn test_full() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_8bit::test::KEYS.clone();

        test_helper::test_full::<ShortintWoppbs8BitSboxPbsAesEncrypt, _>(client_key.as_ref(), &ctx);
    }
}
