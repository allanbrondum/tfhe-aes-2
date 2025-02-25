//! Model with each ciphertext representing 8 bits. Build on `tfhe-rs` `shortint` module with WoP-PBS

use crate::aes_128::fhe::data_model::Byte;
use crate::tfhe::{ClientKeyT, ContextT};
use crate::util;
use rayon::iter::ParallelIterator;

use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign};
use std::sync::Arc;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};

use crate::aes_128::fhe::data_model::BitT;
use crate::tfhe::engine::ShortintEngine;
use tfhe::shortint::wopbs::{ShortintWopbsLUT, WopbsKey};
use tfhe::shortint::{
    CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, ShortintParameterSet,
    WopbsParameters,
};
use tracing::{debug, trace};

/// Parameters created from
///
/// ```text
/// ./optimizer  --min-precision 8 --max-precision 8 --p-error 5.42101086e-20 --ciphertext-modulus-log 64 --wop-pbs
/// security level: 128
/// target p_error: 5.4e-20
/// per precision and log norm2:
///
///   - 8: # bits
///     -ln2:   k,  N,    n, br_l,br_b, ks_l,ks_b, cb_l,cb_b, pp_l,pp_b,  cost, p_error
///     ...
///     - 7 :   2, 10,  785,    6,  7,     8,  2,     4,  6,     3, 12,  12143, 5.4e-20
///     ...
/// ```
fn params() -> ShortintParameterSet {
    let wopbs_params = WopbsParameters {
        lwe_dimension: LweDimension(785),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5140301927925663e-5,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        pbs_level: DecompositionLevelCount(6),
        pbs_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(8),
        ks_base_log: DecompositionBaseLog(2),
        cbs_level: DecompositionLevelCount(4),
        cbs_base_log: DecompositionBaseLog(6),
        pfks_level: DecompositionLevelCount(3),
        pfks_base_log: DecompositionBaseLog(12),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568,
        )),
        message_modulus: MessageModulus(256),
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

impl BitT for BitCt {}

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

/// "Dual" ciphertext representing 8 bits encrypted for bit extraction. Encrypted under GLWE key
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

    pub fn generate_lookup_table(&self, f: impl Fn(u64) -> u64) -> ShortintWopbsLUT {
        let ct = self.server_key.create_trivial(0);
        self.wopbs_key.generate_lut_without_padding(&ct, f).into()
    }

    /// Extract individual bits from 8 bit `shortint`
    pub fn extract_bits_from_ciphertext(&self, ct: &FullWidthCiphertext) -> Byte<BitCt> {
        let start = Instant::now();

        let bit_cts = self.wopbs_key.extract_bits(
            DeltaLog(64 - 8),
            &wrap_in_shortint(ct.clone()),
            ExtractedBitsCount(8),
        );

        let bits = util::collect_array(bit_cts.iter().map(|bit_ct| {
            let start = Instant::now();
            let data = bit_ct.into_container().to_vec();
            trace!("copy bit data {:?}", start.elapsed());

            BitCt::new(
                LweCiphertextOwned::create_from(
                    data,
                    LweCiphertextCreationMetadata {
                        ciphertext_modulus: CiphertextModulus::new_native(),
                    },
                ),
                self.clone(),
            )
        }));

        debug!("extract bits {:?}", start.elapsed());

        Byte::new(bits)
    }

    /// Functional bootstrap of 8 bit `shortint` from individual bits
    pub fn bootstrap_from_bits(
        &self,
        byte: &Byte<BitCt>,
        lut: &ShortintWopbsLUT,
    ) -> FullWidthCiphertext {
        let start = Instant::now();

        assert_eq!(lut.as_ref().output_ciphertext_count(), CiphertextCount(1));

        let lwe_size = byte.bits().find_any(|_| true).unwrap().ct.lwe_size();

        let bit_cts: Vec<_> = byte.bits().map(|bit| bit.ct.as_view()).collect();
        let mut bits_data =
            Vec::with_capacity(bit_cts.iter().map(|bit_ct| bit_ct.as_ref().len()).sum());
        for bit_ct in bit_cts {
            bits_data.extend(bit_ct.as_ref());
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
}

fn wrap_in_shortint(ct: FullWidthCiphertext) -> shortint::Ciphertext {
    shortint::Ciphertext::new(
        ct.ct,
        Degree::new(255),
        NoiseLevel::NOMINAL,
        MessageModulus(256),
        CarryModulus(1),
        PBSOrder::KeyswitchBootstrap,
    )
}

#[cfg(test)]
pub mod test {
    use super::*;

    use crate::aes_128::fhe::fhe_encryption::{decrypt_byte, encrypt_byte};
    use std::sync::{Arc, LazyLock};

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
    fn test_bootstrap_from_bits_trivial_lut() {
        let (client_key, context) = KEYS.clone();

        let byte = 0b10110101;
        let bit_cts = encrypt_byte(client_key.as_ref(), byte);

        let lut = context.generate_lookup_table(|val| val);
        let int_ct = context.bootstrap_from_bits(&bit_cts, &lut);

        let decrypted = client_key
            .shortint_client_key
            .decrypt_without_padding(&wrap_in_shortint(int_ct));
        assert_eq!(decrypted, 0b10110101);
    }

    #[test]
    fn test_bootstrap_from_bits_trivial_lut2() {
        let (client_key, context) = KEYS.clone();

        let byte = 0b10110101;
        let byte_cts = encrypt_byte(client_key.as_ref(), byte);

        let byte2 = 0b01100110;
        let byte2_cts = encrypt_byte(client_key.as_ref(), byte2);

        let byte_cts = byte_cts ^ byte2_cts.clone();

        let lut = context.generate_lookup_table(|val| val);
        let int_ct = context.bootstrap_from_bits(&byte_cts, &lut);

        let decrypted_int_byte = client_key
            .shortint_client_key
            .decrypt_without_padding(&wrap_in_shortint(int_ct))
            as u8;
        let decrypted_bits_byte = decrypt_byte(client_key.as_ref(), &byte_cts);
        assert_eq!(decrypted_int_byte, decrypted_bits_byte);
    }

    #[test]
    fn test_bootstrap_from_bits_lut() {
        let (client_key, context) = KEYS.clone();

        let byte = 0b10110101;
        let byte_ct = encrypt_byte(client_key.as_ref(), byte);

        let lut = context.generate_lookup_table(|val| val + 3);
        let int_ct = context.bootstrap_from_bits(&byte_ct, &lut);

        let decrypted = client_key
            .shortint_client_key
            .decrypt_without_padding(&wrap_in_shortint(int_ct));
        assert_eq!(decrypted, 0b10110101 + 3);
    }

    #[test]
    fn test_extract_bits_from_int_byte() {
        let (client_key, context) = KEYS.clone();

        let int_ct = FullWidthCiphertext::new(
            client_key
                .shortint_client_key
                .encrypt_without_padding(0b10110101)
                .ct,
            context.clone(),
        );
        let byte_ct = context.extract_bits_from_ciphertext(&int_ct);

        let byte = decrypt_byte(client_key.as_ref(), &byte_ct);
        assert_eq!(byte, 0b10110101);
    }
}
