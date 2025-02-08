//! Implementation of AES-128 using 8 bit `shortint` WoP-PBS

use crate::aes_128::fhe::data_model::{Byte, ByteT};
use crate::aes_128::SBOX;
use crate::tfhe::shortint_woppbs_8bit::*;

use rayon::iter::ParallelIterator;

use std::sync::OnceLock;
use std::time::Instant;

use tfhe::shortint::wopbs::ShortintWopbsLUT;
use tracing::debug;

impl ByteT for Byte<BitCt> {
    fn bootstrap_assign(&mut self) {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| context.generate_lookup_table(|byte| byte));

        *self = self.bootstrap_with_lut(context, lut);
    }

    fn aes_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = SBOX_LUT
            .get_or_init(|| context.generate_lookup_table(|byte| SBOX[byte as usize].into()));

        self.bootstrap_with_lut(context, lut)
    }
}

impl Byte<BitCt> {
    fn bootstrap_with_lut(&self, context: &FheContext, lut: &ShortintWopbsLUT) -> Self {
        let start = Instant::now();
        let int_byte = context.bootstrap_from_bits(&self, lut);
        debug!("boot int {:?}", start.elapsed());

        let start = Instant::now();
        let byte = context.extract_bits_from_int_byte(&int_byte);
        debug!("extract bits {:?}", start.elapsed());

        byte
    }
}

#[cfg(test)]
mod test {
    use crate::aes_128::test_helper;
    use crate::logger;
    use tracing::metadata::LevelFilter;

    #[test]
    fn test_two_rounds() {
        logger::init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_8bit::test::KEYS.clone();

        test_helper::test_vs_plain(client_key.as_ref(), &ctx, 2);
    }

    #[test]
    fn test_vs_aes() {
        logger::init(LevelFilter::INFO);

        let (client_key, ctx) = crate::tfhe::shortint_woppbs_8bit::test::KEYS.clone();

        test_helper::test_vs_aes(client_key.as_ref(), &ctx);
    }
}
