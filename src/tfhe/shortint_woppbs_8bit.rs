//! Model with each ciphertext representing 1 bit. Build on `tfhe-rs` `shortint` module but with
//! additional primitives for multivariate function bootstrapping

use crate::aes_128::fhe::data_model::{BitT, Byte};
use crate::util;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::{Debug, Formatter};
use std::iter;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tfhe::core_crypto::algorithms::{
    glwe_sample_extraction, lwe_keyswitch, lwe_programmable_bootstrapping,
};
use tfhe::core_crypto::entities::{
    Cleartext, GlweCiphertext, GlweCiphertextMutView, GlweCiphertextOwned, LweCiphertextView,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::wopbs::{ShortintWopbsLUT, WopbsKey};
use tfhe::shortint::{
    CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, ShortintParameterSet,
    WopbsParameters,
};
use tracing::debug;

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
            1.5140301927925663e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568513645324585951,
        )),
        pbs_base_log: DecompositionBaseLog(7),
        pbs_level: DecompositionLevelCount(6),
        ks_level: DecompositionLevelCount(8),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(3),
        pfks_base_log: DecompositionBaseLog(12),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000022148688116005568513645324585951,
        )),
        cbs_level: DecompositionLevelCount(4),
        cbs_base_log: DecompositionBaseLog(6),
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

#[derive(Clone)]
pub struct BitCt {
    ct: LweCiphertextOwned<u64>,
    noise_level: NoiseLevel,
    context: FheContext,
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
    Plaintext(bit.0 << 63)
}

pub fn decode_bit(encoding: Plaintext<u64>) -> Cleartext<u64> {
    Cleartext(((encoding.0.wrapping_add(1 << 62)) & (1 << 63)) >> 63)
}

impl BitXorAssign<&BitCt> for BitCt {
    fn bitxor_assign(&mut self, rhs: &Self) {
        lwe_linear_algebra::lwe_ciphertext_add_assign(&mut self.ct, &rhs.ct);
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

static CONTEXT: OnceLock<FheContext> = OnceLock::new();

impl Default for BitCt {
    fn default() -> Self {
        <BitCt as BitT>::trivial(Cleartext(0))
    }
}

impl BitT for BitCt {
    fn trivial(bit: Cleartext<u8>) -> Self {
        let context = CONTEXT.get().expect("context").clone();

        let ct = lwe_encryption::allocate_and_trivially_encrypt_new_lwe_ciphertext(
            context
                .server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
            encode_bit(Cleartext(bit.0 as u64)),
            CiphertextModulus::new_native(),
        );

        Self {
            ct,
            noise_level: NoiseLevel::ZERO,
            context,
        }
    }
}

#[derive(Clone)]
pub struct IntByteFhe {
    pub ct: shortint::ciphertext::Ciphertext,
    pub context: FheContext,
}

impl IntByteFhe {
    pub fn new(fhe: shortint::ciphertext::Ciphertext, context: FheContext) -> Self {
        Self { ct: fhe, context }
    }
}

impl IntByteFhe {
    pub fn bootstrap_from_bool_byte(byte: &Byte<BitCt>, lut: &ShortintWopbsLUT) -> Self {
        assert_eq!(lut.as_ref().output_ciphertext_count(), CiphertextCount(1));
        let context = &byte.bits().next().unwrap().context;

        let lwe_size = byte.bits().next().unwrap().ct.lwe_size();

        let bit_cts = byte.bits().map(|bit| bit.ct.as_view());
        let start = Instant::now();
        let bits_data: Vec<u64> = bit_cts
            .flat_map(|bit_ct| bit_ct.into_container().iter().copied())
            .collect();
        debug!("copy bits data {:?}", start.elapsed());

        let bits_list_ct = LweCiphertextListOwned::create_from(
            bits_data,
            LweCiphertextListCreationMetadata {
                lwe_size,
                ciphertext_modulus: CiphertextModulus::new_native(),
            },
        );

        let lwe_ct = context
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut.as_ref(), &bits_list_ct)
            .into_iter()
            .next()
            .expect("one element");

        let sks = &context.wopbs_key.wopbs_server_key;

        let ct = shortint::Ciphertext::new(
            lwe_ct,
            Degree::new(sks.message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            sks.message_modulus,
            sks.carry_modulus,
            PBSOrder::KeyswitchBootstrap,
        );

        Self {
            ct,
            context: context.clone(),
        }
    }

    pub fn generate_lookup_table(context: &FheContext, f: impl Fn(u64) -> u64) -> ShortintWopbsLUT {
        let ct = context.server_key.create_trivial(0);
        context
            .wopbs_key
            .generate_lut_without_padding(&ct, f)
            .into()
    }
}

impl Byte<BitCt> {
    pub fn bootstrap_from_int_byte(int_byte: &IntByteFhe) -> Self {
        let context = &int_byte.context;

        let bit_cts =
            context
                .wopbs_key
                .extract_bits(DeltaLog(64 - 8), &int_byte.ct, ExtractedBitsCount(8));

        let bits = util::collect_array(bit_cts.iter().map(|bit_ct| {
            let start = Instant::now();
            let data = bit_ct.into_container().to_vec();
            debug!("copy bit data {:?}", start.elapsed());

            BitCt::new(
                LweCiphertextOwned::create_from(
                    data,
                    LweCiphertextCreationMetadata {
                        ciphertext_modulus: CiphertextModulus::new_native(),
                    },
                ),
                context.clone(),
            )
        }));

        Self::new(bits)
    }
}

#[derive(Clone)]
pub struct FheContext {
    server_key: Arc<shortint::server_key::ServerKey>,
    wopbs_key: Arc<shortint::wopbs::WopbsKey>,
}

pub struct ClientKey(shortint::ClientKey, FheContext);

impl ClientKey {
    pub fn encrypt(&self, bit: Cleartext<u64>) -> BitCt {
        let (encryption_lwe_sk, encryption_noise_distribution) = (
            &self.0.lwe_secret_key,
            self.0.parameters.lwe_noise_distribution(),
        );

        let ct = ShortintEngine::with_thread_local_mut(|engine| {
            lwe_encryption::allocate_and_encrypt_new_lwe_ciphertext(
                &encryption_lwe_sk,
                encode_bit(bit),
                encryption_noise_distribution,
                self.0.parameters.ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        BitCt::new(ct, self.1.clone())
    }

    pub fn decrypt(&self, bit: &BitCt) -> Cleartext<u64> {
        let encoding = lwe_encryption::decrypt_lwe_ciphertext(&self.0.lwe_secret_key, &bit.ct);
        decode_bit(encoding)
    }
}

impl FheContext {
    pub fn generate_keys() -> (ClientKey, Self) {
        Self::generate_keys_with_params(params())
    }

    fn generate_keys_with_params(params: ShortintParameterSet) -> (ClientKey, Self) {
        let (client_key, server_key) = shortint::gen_keys(params);

        let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&client_key, &server_key);

        let context = FheContext {
            server_key: server_key.into(),
            wopbs_key: wops_key.into(),
        };

        // "hack" to allow creating default and trivial values without passing context around.
        // works as long as we only generate one set of keys in the application
        CONTEXT
            .set(context.clone())
            .map_err(|_| ())
            .expect("context already set");

        (ClientKey(client_key, context.clone()), context)
    }
}
