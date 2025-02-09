//! Implementation of AES-128 using 1 bit `shortint` WoP-PBS

use crate::aes_128::fhe::data_model::{Block, Byte, Word};
use crate::aes_128::SBOX;
use crate::tfhe::shortint_woppbs_1bit::*;

use rayon::iter::ParallelIterator;

use crate::aes_128::fhe::data_model::BitT;
use crate::aes_128::fhe::fhe_sbox_pbs::ByteT;
use crate::aes_128::fhe::{fhe_sbox_pbs, Aes128Encrypt};
use crate::tfhe::ContextT;
use std::sync::OnceLock;
use tfhe::shortint::wopbs::WopbsLUTBase;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = &self.bits().find_first(|_| true).unwrap().context.clone();

        static IDENTITY_LUT: OnceLock<WopbsLUTBase> = OnceLock::new();
        let lut =
            IDENTITY_LUT.get_or_init(|| context.generate_lookup_table(1, 1, |bit| bit as u64));

        self.bits_mut().for_each(|bit| {
            *bit = context
                .circuit_bootstrap(&[bit], lut)
                .into_iter()
                .next()
                .expect("one bit");
        });
    }

    fn sbox_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<WopbsLUTBase> = OnceLock::new();
        let lut = SBOX_LUT
            .get_or_init(|| context.generate_lookup_table(8, 8, |byte| SBOX[byte as usize] as u64));

        let new_bits = context
            .circuit_bootstrap(&self.0.each_ref(), lut)
            .try_into()
            .expect("8 bits");

        Self(new_bits)
    }
}

impl BitT for BitCt {}

pub struct ShortintWoppbs1BitSboxPbsAesEncrypt;

impl Aes128Encrypt for ShortintWoppbs1BitSboxPbsAesEncrypt {
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
    use crate::aes_128::fhe::fhe_sbox_pbs_impls::shortint_woppbs_1bit::ShortintWoppbs1BitSboxPbsAesEncrypt;
    use crate::aes_128::test_helper;
    use crate::logger;
    use tracing::metadata::LevelFilter;

    #[test]
    fn test_light() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_1bit::test::KEYS_LVL_11.clone();

        test_helper::test_light::<ShortintWoppbs1BitSboxPbsAesEncrypt, _>(
            client_key.as_ref(),
            &ctx,
        );
    }

    #[test]
    #[cfg(feature = "long_running_tests")]
    fn test_full() {
        logger::test_init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_1bit::test::KEYS_LVL_11.clone();

        test_helper::test_full::<ShortintWoppbs1BitSboxPbsAesEncrypt, _>(client_key.as_ref(), &ctx);
    }
}
