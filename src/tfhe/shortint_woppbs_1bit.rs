//! Model with each ciphertext representing 1 bit. Build on `tfhe-rs` `shortint` module with WoP-PBS.

mod parameters;

use crate::tfhe::{ClientKeyT, ContextT};

use hashbrown::HashSet;
use rayon::iter::IntoParallelRefIterator;
use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};

use crate::tfhe::engine::ShortintEngine;
use crate::tfhe::shortint_woppbs_1bit::parameters::Shortint1bitWopbsParameters;
use crate::util;
use rayon::iter::ParallelIterator;
use tfhe::shortint::wopbs::{WopbsKey, WopbsLUTBase};
use tfhe::shortint::{CarryModulus, MaxNoiseLevel, MessageModulus};
use tracing::debug;

/// Ciphertext representing a single bit and encrypted for use in circuit bootstrapping. Encrypted under GLWE key
#[derive(Clone)]
pub struct BitCt {
    ct: LweCiphertextOwned<u64>,
    noise_level: NoiseLevelWithComponents,
    pub context: FheContext,
}

#[derive(Clone, Debug)]
pub struct NoiseLevelWithComponents {
    /// Squared noise level (compared to how noise level is used in `shortint` module).
    /// It measures the error/noise variance relative to the "nominal" level (1).
    noise_level_squared: NoiseLevel,
    /// "Ids" of ciphertexts that this one is composed/calculated from. Used to track
    /// if noise/error is independent between ciphertexts
    components: HashSet<CiphertextId>,
}

/// Unique id if each non-trivial ciphertext
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct CiphertextId(u64);

impl NoiseLevelWithComponents {
    fn with_noise_level(noise_level_squared: NoiseLevel, id: CiphertextId) -> Self {
        Self {
            noise_level_squared,
            components: [id].into(),
        }
    }

    fn trivial() -> Self {
        Self {
            noise_level_squared: NoiseLevel::ZERO,
            components: Default::default(),
        }
    }

    fn add_assign(&mut self, rhs: &Self, max_noise_level_squared: MaxNoiseLevel) {
        assert!(
            self.components
                .intersection(&rhs.components)
                .next()
                .is_none(),
            "noise components not independent"
        );
        self.components.extend(&rhs.components);

        self.noise_level_squared += rhs.noise_level_squared;
        max_noise_level_squared
            .validate(self.noise_level_squared)
            .unwrap();
    }
}

impl Debug for BitCt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitCt").field("ct", &self.ct).finish()
    }
}

impl BitCt {
    pub fn fresh(ct: LweCiphertextOwned<u64>, context: FheContext) -> Self {
        Self::with_noise_level(ct, NoiseLevel::NOMINAL, context)
    }

    pub fn with_noise_level(
        ct: LweCiphertextOwned<u64>,
        noise_level_squared: NoiseLevel,
        context: FheContext,
    ) -> Self {
        Self {
            ct,
            noise_level: NoiseLevelWithComponents::with_noise_level(
                noise_level_squared,
                context.next_ct_id(),
            ),
            context,
        }
    }

    pub fn trivial(bit: Cleartext<u64>, context: FheContext) -> Self {
        let ct = lwe_encryption::allocate_and_trivially_encrypt_new_lwe_ciphertext(
            context
                .server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            encode_bit(bit),
            CiphertextModulus::new_native(),
        );

        Self {
            ct,
            noise_level: NoiseLevelWithComponents::trivial(),
            context,
        }
    }
}

pub fn encode_bit(bit: Cleartext<u64>) -> Plaintext<u64> {
    assert!(bit.0 < 2, "cleartext out of bounds: {}", bit.0);
    Plaintext(bit.0 << 63)
}

pub fn decode_bit(encoding: Plaintext<u64>) -> Cleartext<u64> {
    Cleartext(((encoding.0.wrapping_add(1 << 62)) & (1 << 63)) >> 63)
}

impl BitXorAssign<&BitCt> for BitCt {
    fn bitxor_assign(&mut self, rhs: &Self) {
        lwe_linear_algebra::lwe_ciphertext_add_assign(&mut self.ct, &rhs.ct);
        self.noise_level.add_assign(
            &rhs.noise_level,
            self.context.parameters.max_noise_level_squared,
        );
    }
}

impl BitXor for BitCt {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
    }
}

/// Ciphertext representing 1 bit encrypted for bit extraction but encrypted under the LWE key
#[derive(Clone)]
struct DualCiphertext {
    ct: LweCiphertextOwned<u64>,
}

impl DualCiphertext {
    fn new(ct: LweCiphertextOwned<u64>) -> Self {
        Self { ct }
    }
}

#[derive(Clone)]
pub struct FheContext {
    server_key: Arc<shortint::server_key::ServerKey>,
    wopbs_key: Arc<shortint::wopbs::WopbsKey>,
    parameters: Shortint1bitWopbsParameters,
    /// Counter for issuing ids to ciphertexts with noise (non-trivial ciphertexts)
    ct_counter: Arc<AtomicU64>,
}

impl FheContext {
    fn next_ct_id(&self) -> CiphertextId {
        let ct_id = self.ct_counter.fetch_add(1, Ordering::SeqCst);
        CiphertextId(ct_id)
    }
}

impl ContextT for FheContext {
    type Bit = BitCt;

    fn trivial(&self, bit: Cleartext<u64>) -> BitCt {
        BitCt::trivial(bit, self.clone())
    }
}

pub struct ClientKey {
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    #[allow(unused)]
    lwe_secret_key: LweSecretKeyOwned<u64>,
    shortint_client_key: shortint::ClientKey,
    context: FheContext,
}

impl ClientKeyT for ClientKey {
    type Bit = BitCt;

    fn encrypt(&self, bit: Cleartext<u64>) -> BitCt {
        let (encryption_lwe_sk, encryption_noise_distribution) = (
            self.glwe_secret_key.as_lwe_secret_key(),
            self.shortint_client_key.parameters.lwe_noise_distribution(),
        );

        let ct = ShortintEngine::with_thread_local_mut(|engine| {
            lwe_encryption::allocate_and_encrypt_new_lwe_ciphertext(
                &encryption_lwe_sk,
                encode_bit(bit),
                encryption_noise_distribution,
                self.shortint_client_key.parameters.ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        BitCt::fresh(ct, self.context.clone())
    }

    fn decrypt(&self, bit: &BitCt) -> Cleartext<u64> {
        let encoding = lwe_encryption::decrypt_lwe_ciphertext(
            &self.glwe_secret_key.as_lwe_secret_key(),
            &bit.ct,
        );
        decode_bit(encoding)
    }
}

impl FheContext {
    pub fn generate_keys_sqrd_lvl_1() -> (ClientKey, Self) {
        Self::generate_keys_with_params(parameters::params_sqrd_lvl_1())
    }

    pub fn generate_keys_sqrd_lvl_4() -> (ClientKey, Self) {
        Self::generate_keys_with_params(parameters::params_sqrd_lvl_4())
    }

    pub fn generate_keys_sqrd_lvl_64() -> (ClientKey, Self) {
        Self::generate_keys_with_params(parameters::params_sqrd_lvl_64())
    }

    pub fn generate_keys_sqrd_lvl_256() -> (ClientKey, Self) {
        Self::generate_keys_with_params(parameters::params_sqrd_lvl_256())
    }

    fn generate_keys_with_params(parameters: Shortint1bitWopbsParameters) -> (ClientKey, Self) {
        let (shortint_client_key, server_key) = shortint::gen_keys(parameters.inner);

        let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&shortint_client_key, &server_key);

        let context = FheContext {
            server_key: server_key.into(),
            wopbs_key: wops_key.into(),
            parameters,
            ct_counter: Default::default(),
        };

        let (glwe_secret_key, lwe_secret_key, _parameters) =
            shortint_client_key.clone().into_raw_parts();

        let client_key = ClientKey {
            glwe_secret_key,
            lwe_secret_key,
            shortint_client_key,
            context: context.clone(),
        };

        (client_key, context)
    }

    /// Generate lookup table for the given function considering the given number of bits of input and
    /// output (the least significant bits) in the given function. When the returned LUT is used with [`Self::circuit_bootstrap`], the same number of input
    /// bit ciphertexts should be given, and the number of bit ciphertexts returned is the same as the number of output bits
    /// specified in the LUT.
    pub fn generate_lookup_table(
        &self,
        input_bits: usize,
        output_bits: usize,
        f: impl Fn(u16) -> u64,
    ) -> WopbsLUTBase {
        generate_multivariate_luts(
            input_bits,
            output_bits,
            self.wopbs_key
                .wopbs_server_key
                .bootstrapping_key
                .polynomial_size(),
            f,
        )
    }

    /// Circuit bootstrap using with given bits as input
    pub fn circuit_bootstrap(&self, bits: &[&BitCt], lut: &WopbsLUTBase) -> Vec<BitCt> {
        let input_bit_count = bits.len();

        let start = Instant::now();

        let dual_bits: Vec<_> = bits
            .par_iter()
            .map(|bit| self.extract_dual_bit_from_bit(bit))
            .collect();

        let lwe_size = dual_bits[0].ct.lwe_size();

        let mut dual_bits_data = Vec::with_capacity(
            dual_bits
                .iter()
                .map(|dual_bit_ct| dual_bit_ct.ct.as_ref().len())
                .sum(),
        );
        for dual_bit_ct in dual_bits {
            dual_bits_data.extend(dual_bit_ct.ct.as_ref());
        }

        let dual_bits_list_ct = LweCiphertextListOwned::create_from(
            dual_bits_data,
            LweCiphertextListCreationMetadata {
                lwe_size,
                ciphertext_modulus: CiphertextModulus::new_native(),
            },
        );

        // In Lemma 3.2 in https://eprint.iacr.org/2017/430.pdf, the number of "selector"/"controller" input ciphertexts
        // acts as a multiplier on the error variance. Hence, we multiply the (squared) nominal noise level with
        // the number of input bits.
        let output_noise_level_squared = NoiseLevel::NOMINAL * input_bit_count as u64;
        let bit_cts: Vec<_> = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut, &dual_bits_list_ct)
            .into_iter()
            .map(|lwe_ct| BitCt::with_noise_level(lwe_ct, output_noise_level_squared, self.clone()))
            .collect();

        debug!("multivalued circuit bootstrap {:?}", start.elapsed());

        bit_cts
    }

    /// Extract the "dual" single bit from the bit ciphertext. This is effectively just a keyswitch
    fn extract_dual_bit_from_bit(&self, ct: &BitCt) -> DualCiphertext {
        let start = Instant::now();

        let bit_cts = self.wopbs_key.extract_bits(
            DeltaLog(63),
            &wrap_in_shortint(
                ct.ct.clone(),
                NoiseLevel::NOMINAL * ((ct.noise_level.noise_level_squared.get() - 1).isqrt() + 1),
            ),
            ExtractedBitsCount(1),
        );

        let bit_ct = bit_cts.iter().next().expect("one bit");

        let data = bit_ct.into_container().to_vec();

        debug!("extract bit {:?}", start.elapsed());

        DualCiphertext::new(LweCiphertextOwned::create_from(
            data,
            LweCiphertextCreationMetadata {
                ciphertext_modulus: CiphertextModulus::new_native(),
            },
        ))
    }
}

fn generate_multivariate_luts(
    input_bits: usize,
    output_bits: usize,
    polynomial_size: PolynomialSize,
    f: impl Fn(u16) -> u64,
) -> WopbsLUTBase {
    assert!(0 < input_bits && input_bits <= 16);
    assert!(0 < output_bits && output_bits <= 64);

    let polynomial_size_log = polynomial_size.0.ilog2();
    assert_eq!(polynomial_size.0, 1 << polynomial_size_log);

    let polynomial_tree_bits = (input_bits as u32).saturating_sub(polynomial_size_log);

    let mut lut = WopbsLUTBase::new(
        PlaintextCount(polynomial_size.0 << polynomial_tree_bits),
        CiphertextCount(output_bits),
    );

    // The LUT for circuit bootstrap contains one polynomial per output "sub-function". And each
    // polynomial is a vertical packing of the function evaluations, one input value per monomial.
    // See lwe_wopbs::circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized
    for output_bit in 0..output_bits {
        for (val, value) in lut
            .get_small_lut_mut(output_bit)
            .iter_mut()
            .enumerate()
            .take(1 << input_bits)
        {
            *value = encode_bit(Cleartext(
                util::u64_to_bits(f(val as u16))[output_bit + 64 - output_bits] as u64,
            ))
            .0;
        }
    }

    lut
}

fn wrap_in_shortint(
    lwe_ct: LweCiphertextOwned<u64>,
    noise_level: NoiseLevel,
) -> shortint::Ciphertext {
    shortint::Ciphertext::new(
        lwe_ct,
        Degree::new(1),
        noise_level,
        MessageModulus(2),
        CarryModulus(1),
        PBSOrder::KeyswitchBootstrap,
    )
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::array;

    use crate::{logger, util};
    use std::sync::{Arc, LazyLock};
    use tracing::level_filters::LevelFilter;

    pub static KEYS_SQRD_LVL_1: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(parameters::params_sqrd_lvl_1()));

    pub static KEYS_SQRD_LVL_4: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(parameters::params_sqrd_lvl_4()));

    pub static KEYS_SQRD_LVL_64: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(parameters::params_sqrd_lvl_64()));

    pub static KEYS_SQRD_LVL_256: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(parameters::params_sqrd_lvl_256()));

    fn keys_impl(params: Shortint1bitWopbsParameters) -> (Arc<ClientKey>, FheContext) {
        let (client_key, context) = FheContext::generate_keys_with_params(params);
        (client_key.into(), context)
    }

    #[test]
    fn test_encode() {
        assert_eq!(encode_bit(Cleartext(0)), Plaintext(0));
        assert_eq!(encode_bit(Cleartext(1)), Plaintext(1 << 63));
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode_bit(Plaintext(0)), Cleartext(0));
        assert_eq!(decode_bit(Plaintext(1)), Cleartext(0));
        assert_eq!(decode_bit(Plaintext(u64::MAX)), Cleartext(0));
        assert_eq!(decode_bit(Plaintext(1 << 63)), Cleartext(1));
        assert_eq!(decode_bit(Plaintext((1 << 63) - 1)), Cleartext(1));
        assert_eq!(decode_bit(Plaintext((1 << 63) + 1)), Cleartext(1));
    }

    #[test]
    fn test_bit_encrypt_decrypt() {
        let (client_key, context) = KEYS_SQRD_LVL_1.clone();

        let b1 = client_key.encrypt(Cleartext(0));
        let b2 = client_key.encrypt(Cleartext(1));

        assert_eq!(client_key.decrypt(&b1), Cleartext(0));
        assert_eq!(client_key.decrypt(&b2), Cleartext(1));

        // decrypt trivial
        assert_eq!(
            client_key.decrypt(&BitCt::trivial(Cleartext(0), context.clone())),
            Cleartext(0)
        );
        assert_eq!(
            client_key.decrypt(&BitCt::trivial(Cleartext(1), context.clone())),
            Cleartext(1)
        );
    }

    #[test]
    fn test_bit_xor() {
        let (client_key, context) = KEYS_SQRD_LVL_4.clone();

        let b1 = client_key.encrypt(Cleartext(0));
        let b2 = client_key.encrypt(Cleartext(1));
        let b3 = client_key.encrypt(Cleartext(0));
        let b4 = client_key.encrypt(Cleartext(1));

        // xor
        assert_eq!(client_key.decrypt(&(b1.clone() ^ b2.clone())), Cleartext(1));
        assert_eq!(client_key.decrypt(&(b1.clone() ^ b3.clone())), Cleartext(0));
        assert_eq!(client_key.decrypt(&(b2.clone() ^ b4.clone())), Cleartext(0));

        // trivial
        let t0 = BitCt::trivial(Cleartext(0), context.clone());
        assert_eq!(client_key.decrypt(&(b2.clone() ^ t0.clone())), Cleartext(1));
        // trivial does not accumulate noise
        let _ = t0.clone() ^ t0.clone() ^ t0.clone();
    }

    #[test]
    #[should_panic(expected = "NoiseTooBig")]
    fn test_bit_xor_above_max_noise() {
        let (client_key, _context) = KEYS_SQRD_LVL_4.clone();

        let b1 = client_key.encrypt(Cleartext(0));
        let b2 = client_key.encrypt(Cleartext(1));
        let b3 = client_key.encrypt(Cleartext(0));
        let b4 = client_key.encrypt(Cleartext(1));
        let b5 = client_key.encrypt(Cleartext(0));

        // noise accumulation
        let _ = b1.clone() ^ b2.clone() ^ b3.clone() ^ b4.clone() ^ b5.clone();
    }

    #[test]
    #[should_panic(expected = "noise components not independent")]
    fn test_bit_xor_not_independent() {
        let (client_key, _context) = KEYS_SQRD_LVL_4.clone();

        let b1 = client_key.encrypt(Cleartext(0));

        // ciphertexts with dependent noise
        let _ = b1.clone() ^ b1.clone();
    }

    #[test]
    fn test_multivariate_parity_fn_3() {
        logger::test_init(LevelFilter::DEBUG);

        test_multivariate_parity_fn_impl(3, 0b001);
        test_multivariate_parity_fn_impl(3, 0b000);
        test_multivariate_parity_fn_impl(3, 0b100);
        test_multivariate_parity_fn_impl(3, 0b101);
    }

    #[test]
    fn test_multivariate_parity_fn_8() {
        logger::test_init(LevelFilter::DEBUG);

        test_multivariate_parity_fn_impl(8, 0b11001001);
        test_multivariate_parity_fn_impl(8, 0b01001001);
        test_multivariate_parity_fn_impl(8, 0b00101010);
        test_multivariate_parity_fn_impl(8, 0b11011001);
    }

    fn test_multivariate_parity_fn_impl(bits: usize, word: u16) {
        let (client_key, context) = KEYS_SQRD_LVL_64.clone();

        let parity_fn =
            |val: u16| -> u64 { (util::u16_to_bits(val).iter().sum::<u8>() % 2) as u64 };

        // println!("parity {}", parity_fn(byte).0);

        let bit_cts = util::u16_to_bits(word).map(|bit| client_key.encrypt(Cleartext(bit as u64)));

        // let bits_cl:Vec<_> = bit_cts.each_ref()[8 - bits..].iter().map(|ct| client_key.decrypt(&ct)).collect();
        // println!("bits {:?}", bits_cl);

        let tv = context.generate_lookup_table(bits, 1, parity_fn);
        let d = context
            .circuit_bootstrap(&bit_cts.each_ref()[16 - bits..], &tv)
            .into_iter()
            .next()
            .expect("one bit");

        assert_eq!(client_key.decrypt(&d).0, parity_fn(word));
    }

    #[test]
    fn test_multivariate_multivalues_square_fn_3() {
        logger::test_init(LevelFilter::DEBUG);

        test_multivariate_multivalued_square_fn_impl(3, 0b101);
        test_multivariate_multivalued_square_fn_impl(3, 0b000);
        test_multivariate_multivalued_square_fn_impl(3, 0b100);
        test_multivariate_multivalued_square_fn_impl(3, 0b101);
    }

    #[test]
    fn test_multivariate_multivalues_square_fn_8() {
        logger::test_init(LevelFilter::DEBUG);

        test_multivariate_multivalued_square_fn_impl(8, 0b11001001);
        test_multivariate_multivalued_square_fn_impl(8, 0b01001001);
        test_multivariate_multivalued_square_fn_impl(8, 0b00101010);
        test_multivariate_multivalued_square_fn_impl(8, 0b11011001);
    }

    fn test_multivariate_multivalued_square_fn_impl(bits: usize, byte: u16) {
        let (client_key, context) = KEYS_SQRD_LVL_64.clone();

        let square_fn = |val: u16| -> u64 { (val * val % (1 << bits)) as u64 };

        let bit_cts = util::u16_to_bits(byte).map(|bit| client_key.encrypt(Cleartext(bit as u64)));

        // let bits_cl:Vec<_> = bit_cts.each_ref()[8 - bits..].iter().map(|ct| client_key.decrypt(&ct)).collect();
        // println!("bits {:?}", bits_cl);

        let tv = context.generate_lookup_table(bits, bits, square_fn);
        let out = context.circuit_bootstrap(&bit_cts.each_ref()[16 - bits..], &tv);

        let out_clear: Vec<_> = out.into_iter().map(|d| client_key.decrypt(&d)).collect();
        let out_bits: [u8; 64] = array::from_fn(|i| {
            out_clear
                .get(i - 64 + bits)
                .map(|bit| bit.0 as u8)
                .unwrap_or_default()
        });
        let out_byte = util::bits_to_u64(out_bits);

        assert_eq!(out_byte, square_fn(byte));
    }

    #[test]
    fn test_multivariate_multivalues_perf_8() {
        logger::test_init(LevelFilter::DEBUG);

        test_multivariate_multivalued_square_fn_impl(8, 0b11001001);
    }

    #[test]
    fn test_multivariate_multivalues_xor_8bit() {
        logger::test_init(LevelFilter::DEBUG);

        let (client_key, context) = KEYS_SQRD_LVL_1.clone();

        let b1 = 0b11000110;
        let b2 = 0b10101010;
        let word = u16::from_be_bytes([b1, b2]);

        let xor_fn = |val: u16| -> u64 {
            let [b1, b2] = val.to_be_bytes();
            (b1 ^ b2) as u64
        };

        let bit_cts = util::u16_to_bits(word).map(|bit| client_key.encrypt(Cleartext(bit as u64)));

        // let bits_cl:Vec<_> = bit_cts.each_ref()[8 - bits..].iter().map(|ct| client_key.decrypt(&ct)).collect();
        // println!("bits {:?}", bits_cl);

        let tv = context.generate_lookup_table(16, 8, xor_fn);
        let out = context.circuit_bootstrap(&bit_cts.each_ref(), &tv);

        let out_clear: Vec<_> = out.into_iter().map(|d| client_key.decrypt(&d)).collect();
        let out_bits: [u8; 64] = array::from_fn(|i| {
            out_clear
                .get(i - 64 + 8)
                .map(|bit| bit.0 as u8)
                .unwrap_or_default()
        });
        let out_byte = util::bits_to_u64(out_bits);

        assert_eq!(out_byte, xor_fn(word));
    }

    fn encode_bits<const N: usize>(bits: [u8; N]) -> [u64; N] {
        bits.map(|b| encode_bit(Cleartext(b as u64)).0)
    }

    #[test]
    fn test_generate_multivariate_luts_vertical_packing() {
        let lut = generate_multivariate_luts(3, 2, PolynomialSize(16), |val| val as u64);
        assert_eq!(lut.as_ref().len(), 16 * 2);
        assert_eq!(
            lut.get_small_lut(0),
            &encode_bits([0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            lut.get_small_lut(1),
            &encode_bits([0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn test_generate_multivariate_luts_multipolynomial_vertical_packing() {
        let lut = generate_multivariate_luts(5, 2, PolynomialSize(8), |val| val as u64);
        assert_eq!(lut.as_ref().len(), 8 * 4 * 2);
        assert_eq!(
            lut.get_small_lut(0),
            &encode_bits([
                0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1,
                0, 0, 1, 1
            ])
        );
        assert_eq!(
            lut.get_small_lut(1),
            &encode_bits([
                0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                0, 1, 0, 1
            ])
        );
    }

    #[test]
    fn test_noise_independence() {
        let (client_key, context) = KEYS_SQRD_LVL_1.clone();

        let b1 = client_key.encrypt(Cleartext(0));
        let b2 = client_key.encrypt(Cleartext(0));

        ciphertext_debug(&client_key, "b1", &b1);
        ciphertext_debug(&client_key, "b1", &b1);
        ciphertext_debug(&client_key, "b2", &b2);

        let b1_boot1 = boot(&context, &b1);
        let b1_boot2 = boot(&context, &b1);
        let b2_boot1 = boot(&context, &b2);

        ciphertext_debug(&client_key, "b1_boot1", &b1_boot1);
        ciphertext_debug(&client_key, "b1_boot2", &b1_boot2);
        ciphertext_debug(&client_key, "b2_boot1", &b2_boot1);
    }

    fn ciphertext_debug(client_key: &ClientKey, label: &str, bit: &BitCt) {
        let encoding = lwe_encryption::decrypt_lwe_ciphertext(
            &client_key.glwe_secret_key.as_lwe_secret_key(),
            &bit.ct,
        );
        let noise = encoding.0 - encode_bit(decode_bit(encoding)).0;
        println!("noise {}: {:064b}", label, noise);
    }

    fn boot(context: &FheContext, bit: &BitCt) -> BitCt {
        let lut = context.generate_lookup_table(1, 1, |bit| bit as u64);

        context
            .circuit_bootstrap(&[bit], &lut)
            .into_iter()
            .next()
            .expect("one bit")
    }
}
