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
    fn bootstrap(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = IDENTITY_LUT.get_or_init(|| IntByte::generate_lookup_table(context, |byte| byte));

        self.bootstrap_with_lut(lut)
    }

    fn aes_substitute(&self) -> Self {
        let context = &self.bits().find_first(|_| true).unwrap().context;

        static SBOX_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
        let lut = SBOX_LUT.get_or_init(|| {
            IntByte::generate_lookup_table(context, |byte| SBOX[byte as usize].into())
        });

        self.bootstrap_with_lut(lut)
    }
}

impl Byte<BitCt> {
    fn bootstrap_with_lut(&self, lut: &ShortintWopbsLUT) -> Self {
        let start = Instant::now();
        let int_byte = IntByte::bootstrap_from_bits(self, lut);
        debug!("boot int {:?}", start.elapsed());

        let start = Instant::now();
        let byte = Byte::extract_bits_from_int_byte(&int_byte);
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

        // rayon::ThreadPoolBuilder::new()
        //     .num_threads(16)
        //     .build_global()
        //     .unwrap();
        // debug!("current_num_threads: {}", rayon::current_num_threads());

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
