//! Model with each ciphertext representing 1 bit. Build on `tfhe-rs` `shortint` module with WoP-PBS.

use crate::tfhe::{ClientKeyT, ContextT};

use rayon::iter::IntoParallelRefIterator;
use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign};
use std::sync::Arc;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};

use crate::util;
use rayon::iter::ParallelIterator;
use tfhe::shortint::wopbs::{WopbsKey, WopbsLUTBase};
use tfhe::shortint::{
    CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, ShortintParameterSet,
    WopbsParameters,
};
use tracing::debug;

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 5 :   2, 10,  649,    6,  7,     6,  2,     1, 15,     3, 12,    268, 4.8e-20
/// ...
/// ```
fn params_lvl_5() -> ShortintParameterSet {
    let wopbs_params = WopbsParameters {
        lwe_dimension: LweDimension(649),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(6),
        pbs_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(15),
        pfks_level: DecompositionLevelCount(3),
        pfks_base_log: DecompositionBaseLog(12),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    let pbs_params = ClassicPBSParameters {
        lwe_dimension: wopbs_params.lwe_dimension,
        glwe_dimension: wopbs_params.glwe_dimension,
        polynomial_size: wopbs_params.polynomial_size,
        lwe_noise_distribution: wopbs_params.lwe_noise_distribution,
        glwe_noise_distribution: wopbs_params.glwe_noise_distribution,
        pbs_base_log: wopbs_params.pbs_base_log,
        pbs_level: wopbs_params.pbs_level,
        ks_base_log: wopbs_params.ks_base_log,
        ks_level: wopbs_params.ks_level,
        message_modulus: wopbs_params.message_modulus,
        carry_modulus: wopbs_params.carry_modulus,
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -64.074,
        ciphertext_modulus: wopbs_params.ciphertext_modulus,
        encryption_key_choice: wopbs_params.encryption_key_choice,
    };

    ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
}

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 1 --max-precision 1 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
/// - 1: # bits
/// -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
/// ...
/// - 7 :   4,  9,  661,    3, 12,     6,  2,     2,  9,     2, 16,    353, 5.3e-20
/// ...
/// ```
fn params_lvl_11() -> ShortintParameterSet {
    let wopbs_params = WopbsParameters {
        lwe_dimension: LweDimension(661),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.676348397087967e-5,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_level: DecompositionLevelCount(3),
        pbs_base_log: DecompositionBaseLog(12),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(16),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    let pbs_params = ClassicPBSParameters {
        lwe_dimension: wopbs_params.lwe_dimension,
        glwe_dimension: wopbs_params.glwe_dimension,
        polynomial_size: wopbs_params.polynomial_size,
        lwe_noise_distribution: wopbs_params.lwe_noise_distribution,
        glwe_noise_distribution: wopbs_params.glwe_noise_distribution,
        pbs_base_log: wopbs_params.pbs_base_log,
        pbs_level: wopbs_params.pbs_level,
        ks_base_log: wopbs_params.ks_base_log,
        ks_level: wopbs_params.ks_level,
        message_modulus: wopbs_params.message_modulus,
        carry_modulus: wopbs_params.carry_modulus,
        max_noise_level: MaxNoiseLevel::new(11),
        log2_p_fail: -64.074,
        ciphertext_modulus: wopbs_params.ciphertext_modulus,
        encryption_key_choice: wopbs_params.encryption_key_choice,
    };

    ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
}

/// Ciphertext representing a single bit and encrypted for use in circuit bootstrapping. Encrypted under GLWE key
#[derive(Clone)]
pub struct BitCt {
    ct: shortint::Ciphertext,
    pub context: FheContext,
}

impl Debug for BitCt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitCt").field("ct", &self.ct).finish()
    }
}

impl BitCt {
    pub fn new(ct: shortint::Ciphertext, context: FheContext) -> Self {
        Self { ct, context }
    }

    fn trivial(bit: Cleartext<u64>, context: FheContext) -> Self {
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
            ct: wrap_in_shortint(ct, NoiseLevel::ZERO),
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
        self.context
            .server_key
            .unchecked_add_assign(&mut self.ct, &rhs.ct);
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
}

impl ContextT for FheContext {
    type Bit = BitCt;

    fn trivial(&self, bit: Cleartext<u64>) -> BitCt {
        BitCt::trivial(bit, self.clone())
    }
}

pub struct ClientKey {
    shortint_client_key: shortint::ClientKey,
    context: FheContext,
}

impl ClientKeyT for ClientKey {
    type Bit = BitCt;

    fn encrypt(&self, bit: Cleartext<u64>) -> BitCt {
        let ct = self.shortint_client_key.encrypt_without_padding(bit.0);

        BitCt::new(ct, self.context.clone())
    }

    fn decrypt(&self, bit: &BitCt) -> Cleartext<u64> {
        Cleartext(self.shortint_client_key.decrypt_without_padding(&bit.ct))
    }
}

impl FheContext {
    /// Model allowing 11 (max noise level) leveled operations
    pub fn generate_keys_lvl_11() -> (ClientKey, Self) {
        Self::generate_keys_with_params(params_lvl_11())
    }

    /// Model allowing 5 (max noise level) leveled operations
    pub fn generate_keys_lvl_5() -> (ClientKey, Self) {
        Self::generate_keys_with_params(params_lvl_5())
    }

    fn generate_keys_with_params(params: ShortintParameterSet) -> (ClientKey, Self) {
        let (shortint_client_key, server_key) = shortint::gen_keys(params);

        let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&shortint_client_key, &server_key);

        let context = FheContext {
            server_key: server_key.into(),
            wopbs_key: wops_key.into(),
        };

        let client_key = ClientKey {
            shortint_client_key,
            context: context.clone(),
        };

        (client_key, context)
    }

    /// Generate lookup table for the given function considering the given number of bits of input and
    /// output (the least significant bits) in the given function. When the returned LUT is used with [`Self::circuit_bootstrap`], the same number of input
    /// bits should be given, and the number of "dual" ciphertexts returned is the same as the number of output bits
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

        let bit_cts: Vec<_> = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut, &dual_bits_list_ct)
            .into_iter()
            .map(|lwe_ct| BitCt::new(wrap_in_shortint(lwe_ct, NoiseLevel::NOMINAL), self.clone()))
            .collect();

        debug!("multivalued circuit bootstrap {:?}", start.elapsed());

        bit_cts
    }

    /// Extract the "dual" single bit from the bit ciphertext. This is effectively just a keyswitch
    fn extract_dual_bit_from_bit(&self, ct: &BitCt) -> DualCiphertext {
        let start = Instant::now();

        let bit_cts = self
            .wopbs_key
            .extract_bits(DeltaLog(63), &ct.ct, ExtractedBitsCount(1));

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
    // Current implementation only packs one polynomial per output. We can pack more if needed,
    // see lwe_wopbs::circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized
    assert!((1 << input_bits) <= polynomial_size.0);
    assert!(0 < input_bits && input_bits <= 16);
    assert!(0 < output_bits && output_bits <= 64);

    let mut lut = WopbsLUTBase::new(
        PlaintextCount(polynomial_size.0),
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

    pub static KEYS_LVL_5: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(params_lvl_5()));

    pub static KEYS_LVL_11: LazyLock<(Arc<ClientKey>, FheContext)> =
        LazyLock::new(|| keys_impl(params_lvl_11()));

    fn keys_impl(params: ShortintParameterSet) -> (Arc<ClientKey>, FheContext) {
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
    fn test_bit() {
        let (client_key, context) = KEYS_LVL_5.clone();

        let b1 = client_key.encrypt(Cleartext(0));
        let b2 = client_key.encrypt(Cleartext(1));

        assert_eq!(client_key.decrypt(&b1), Cleartext(0));
        assert_eq!(client_key.decrypt(&b2), Cleartext(1));

        assert_eq!(client_key.decrypt(&(b1.clone() ^ b2.clone())), Cleartext(1));
        assert_eq!(client_key.decrypt(&(b1.clone() ^ b1.clone())), Cleartext(0));
        assert_eq!(client_key.decrypt(&(b2.clone() ^ b2.clone())), Cleartext(0));

        // default/trivial
        assert_eq!(
            client_key.decrypt(&(b2.clone() ^ BitCt::trivial(Cleartext(0), context.clone()))),
            Cleartext(1)
        );
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
        let (client_key, context) = KEYS_LVL_5.clone();

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
        let (client_key, context) = KEYS_LVL_5.clone();

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
}
