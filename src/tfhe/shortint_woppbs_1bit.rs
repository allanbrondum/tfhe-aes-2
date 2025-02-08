//! Model with each ciphertext representing 1 bit. Build on `tfhe-rs` `shortint` module with WoP-PBS

use crate::tfhe::{ClientKeyT, ContextT};

use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign};
use std::sync::Arc;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};

use crate::tfhe::engine::ShortintEngine;
use tfhe::shortint::wopbs::{ShortintWopbsLUT, WopbsKey};
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
/// - 7 :   4,  9,  661,    3, 12,     6,  2,     2,  9,     2, 16,    353, 5.3e-20
/// ...
/// ```
fn params() -> ShortintParameterSet {
    let wopbs_params = WopbsParameters {
        lwe_dimension: LweDimension(661),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5140301927925663e-5,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
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
        max_noise_level: MaxNoiseLevel::new(11),
        log2_p_fail: -64.074,
        ciphertext_modulus: wopbs_params.ciphertext_modulus,
        encryption_key_choice: wopbs_params.encryption_key_choice,
    };

    ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
}

/// Ciphertext representing a single bit and encrypted for use in circuit bootstrapping
#[derive(Clone)]
pub struct BitCt {
    ct: LweCiphertextOwned<u64>,
    noise_level: NoiseLevel,
    pub context: FheContext,
}

impl Debug for BitCt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitCt")
            .field("ct", &self.ct)
            .field("noise_level", &self.noise_level)
            .finish()
    }
}

impl BitCt {
    pub fn new(fhe: LweCiphertextOwned<u64>, context: FheContext) -> Self {
        Self {
            ct: fhe,
            noise_level: NoiseLevel::NOMINAL,
            context,
        }
    }

    fn trivial(bit: Cleartext<u64>, context: FheContext) -> Self {
        let ct = lwe_encryption::allocate_and_trivially_encrypt_new_lwe_ciphertext(
            context
                .server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
            encode_bit(bit),
            CiphertextModulus::new_native(),
        );

        Self {
            ct,
            noise_level: NoiseLevel::ZERO,
            context,
        }
    }

    fn set_noise_level(&mut self, noise_level: NoiseLevel) {
        self.context
            .server_key
            .max_noise_level
            .validate(noise_level)
            .unwrap();

        self.noise_level = noise_level;
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
        #[allow(clippy::suspicious_op_assign_impl)]
        self.set_noise_level(self.noise_level + rhs.noise_level);
    }
}

impl BitXor for BitCt {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
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
    #[allow(unused)]
    glwe_secret_key: GlweSecretKeyOwned<u64>,
    lwe_secret_key: LweSecretKeyOwned<u64>,
    shortint_client_key: shortint::ClientKey,
    context: FheContext,
}

impl ClientKeyT for ClientKey {
    type Bit = BitCt;

    fn encrypt(&self, bit: Cleartext<u64>) -> BitCt {
        let (encryption_lwe_sk, encryption_noise_distribution) = (
            &self.lwe_secret_key,
            self.shortint_client_key.parameters.lwe_noise_distribution(),
        );

        let ct = ShortintEngine::with_thread_local_mut(|engine| {
            lwe_encryption::allocate_and_encrypt_new_lwe_ciphertext(
                encryption_lwe_sk,
                encode_bit(bit),
                encryption_noise_distribution,
                self.shortint_client_key.parameters.ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        BitCt::new(ct, self.context.clone())
    }

    fn decrypt(&self, bit: &BitCt) -> Cleartext<u64> {
        let encoding = lwe_encryption::decrypt_lwe_ciphertext(&self.lwe_secret_key, &bit.ct);
        decode_bit(encoding)
    }
}

impl FheContext {
    pub fn generate_keys() -> (ClientKey, Self) {
        Self::generate_keys_with_params(params())
    }

    fn generate_keys_with_params(params: ShortintParameterSet) -> (ClientKey, Self) {
        let (shortint_client_key, server_key) = shortint::gen_keys(params);

        let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&shortint_client_key, &server_key);

        let context = FheContext {
            server_key: server_key.into(),
            wopbs_key: wops_key.into(),
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

    pub fn generate_multivariate_lookup_table(
        &self,
        bits: usize,
        f: impl Fn(u8) -> Cleartext<u64>,
    ) -> ShortintWopbsLUT {
        generate_multivariate_lut(
            bits,
            self.wopbs_key
                .wopbs_server_key
                .bootstrapping_key
                .polynomial_size(),
            f,
        )
        .into()
    }

    /// Functional bootstrap of 8 bit `shortint` from individual bits
    pub fn bootstrap_from_bits(
        &self,
        bits: &[&BitCt],
        lut: &ShortintWopbsLUT,
    ) -> FullWidthCiphertext {
        let start = Instant::now();
        assert_eq!(lut.as_ref().output_ciphertext_count(), CiphertextCount(1));

        let lwe_size = bits[0].ct.lwe_size();

        let mut bits_data =
            Vec::with_capacity(bits.iter().map(|bit_ct| bit_ct.ct.as_ref().len()).sum());
        for bit_ct in bits {
            bits_data.extend(bit_ct.ct.as_ref());
        }

        let bits_list_ct = LweCiphertextListOwned::create_from(
            bits_data,
            LweCiphertextListCreationMetadata {
                lwe_size,
                ciphertext_modulus: CiphertextModulus::new_native(),
            },
        );

        let lwe_ct = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut.as_ref(), &bits_list_ct)
            .into_iter()
            .next()
            .expect("one element");

        debug!("circuit bootstrap {:?}", start.elapsed());

        FullWidthCiphertext::new(lwe_ct, self.clone())
    }

    pub fn extract_bit_from_bit(&self, ct: &FullWidthCiphertext) -> BitCt {
        let start = Instant::now();

        let shortint_ct = shortint::Ciphertext::new(
            ct.ct.clone(),
            Degree::new(1),
            NoiseLevel::NOMINAL,
            MessageModulus(2),
            CarryModulus(1),
            PBSOrder::KeyswitchBootstrap,
        );

        let bit_cts =
            self.wopbs_key
                .extract_bits(DeltaLog(63), &shortint_ct, ExtractedBitsCount(1));

        let bit_ct = bit_cts.iter().next().expect("one bit");

        let data = bit_ct.into_container().to_vec();

        debug!("extract bit {:?}", start.elapsed());

        BitCt::new(
            LweCiphertextOwned::create_from(
                data,
                LweCiphertextCreationMetadata {
                    ciphertext_modulus: CiphertextModulus::new_native(),
                },
            ),
            self.clone(),
        )
    }
}

fn generate_multivariate_lut(
    bits: usize,
    polynomial_size: PolynomialSize,
    f: impl Fn(u8) -> Cleartext<u64>,
) -> Vec<u64> {
    assert!(0 < bits && bits <= 8);

    let basis = 1 << bits;
    let mut vec_lut = vec![0; polynomial_size.0];
    for (i, value) in vec_lut.iter_mut().enumerate().take(basis as usize) {
        assert!(i < 256);
        *value = encode_bit(f(i as u8)).0;
    }
    vec_lut
}

/// Ciphertext representing 1 bit encrypted for bit extraction
#[derive(Clone)]
pub struct FullWidthCiphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub context: FheContext,
}

impl FullWidthCiphertext {
    pub fn new(ct: LweCiphertextOwned<u64>, context: FheContext) -> Self {
        Self { ct, context }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use crate::{logger, util};
    use std::sync::{Arc, LazyLock};
    use tracing::level_filters::LevelFilter;

    pub static KEYS: LazyLock<(Arc<ClientKey>, FheContext)> = LazyLock::new(keys_impl);

    fn keys_impl() -> (Arc<ClientKey>, FheContext) {
        let (client_key, context) = FheContext::generate_keys();
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
        let (client_key, context) = KEYS.clone();

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
    fn test_bivariate_parity_fn_3() {
        logger::test_init(LevelFilter::DEBUG);

        test_bivariate_parity_fn_impl(3, 0b001);
        test_bivariate_parity_fn_impl(3, 0b000);
        test_bivariate_parity_fn_impl(3, 0b100);
        test_bivariate_parity_fn_impl(3, 0b101);
    }

    #[test]
    fn test_bivariate_parity_fn_8() {
        logger::test_init(LevelFilter::DEBUG);

        test_bivariate_parity_fn_impl(8, 0b11001001);
        test_bivariate_parity_fn_impl(8, 0b01001001);
        test_bivariate_parity_fn_impl(8, 0b00101010);
        test_bivariate_parity_fn_impl(8, 0b11011001);
    }

    fn test_bivariate_parity_fn_impl(bits: usize, byte: u8) {
        let (client_key, context) = KEYS.clone();

        let parity_fn = |index: u8| -> Cleartext<u64> {
            Cleartext((util::byte_to_bits(index).iter().sum::<u8>() % 2) as u64)
        };

        // println!("parity {}", parity_fn(byte).0);

        let bit_cts = util::byte_to_bits(byte).map(|bit| client_key.encrypt(Cleartext(bit as u64)));

        // let bits_cl:Vec<_> = bit_cts.each_ref()[8 - bits..].iter().map(|ct| client_key.decrypt(&ct)).collect();
        // println!("bits {:?}", bits_cl);

        let tv = context.generate_multivariate_lookup_table(bits, parity_fn);
        let d = context.bootstrap_from_bits(&bit_cts.each_ref()[8 - bits..], &tv);
        let d = context.extract_bit_from_bit(&d);

        assert_eq!(client_key.decrypt(&d), parity_fn(byte));
    }
}
