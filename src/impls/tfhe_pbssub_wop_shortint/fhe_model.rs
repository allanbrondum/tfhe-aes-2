use crate::impls::tfhe_pbssub_wop_shortint::model::{BoolByte, State, Word};
use crate::impls::tfhe_pbssub_wop_shortint::{FheContext, BOOL_FHE_DEFAULT, INT_BYTE_FHE_DEFAULT};
use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::{Debug, Formatter};
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::time::Instant;
use std::{fmt, mem};
use tfhe::core_crypto::algorithms::{lwe_encryption, lwe_linear_algebra};
use tfhe::core_crypto::entities::{
    lwe_ciphertext, LweCiphertextCreationMetadata, LweCiphertextOwned,
};
use tfhe::core_crypto::prelude::{
    CiphertextCount, CiphertextModulus, ContiguousEntityContainer, CreateFrom, DeltaLog,
    ExtractedBitsCount, LweCiphertextListCreationMetadata, LweCiphertextListOwned, Plaintext,
};
use tfhe::shortint;
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::wopbs::ShortintWopbsLUT;
use tfhe::shortint::PBSOrder;

const NOISE_ASSERT: bool = true;
const PLAIN_CHECK: bool = true;

pub type BlockFhe = [BoolByteFhe; 16];

#[derive(Clone)]
pub struct BoolFhe {
    ct: LweCiphertextOwned<u64>,
    noise_level: NoiseLevel,
    pub context: FheContext,
}

impl BoolFhe {
    pub fn new(fhe: LweCiphertextOwned<u64>, context: FheContext) -> Self {
        Self {
            ct: fhe,
            noise_level: NoiseLevel::NOMINAL,
            context,
        }
    }

    pub fn trivial(b: bool, context: FheContext) -> Self {
        let ct = lwe_encryption::allocate_and_trivially_encrypt_new_lwe_ciphertext(
            context
                .server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
            Self::encode(b),
            CiphertextModulus::new_native(),
        );

        Self {
            ct,
            noise_level: NoiseLevel::ZERO,
            context,
        }
    }

    pub fn encode(b: bool) -> Plaintext<u64> {
        Plaintext(u64::from(b) << 63)
    }

    pub fn decode(encoding: Plaintext<u64>) -> bool {
        ((encoding.0.wrapping_add(1 << 62)) & (1 << 63)) != 0
    }

    fn set_noise_level(&mut self, noise_level: NoiseLevel) {
        if NOISE_ASSERT {
            self.context
                .server_key
                .max_noise_level
                .validate(noise_level)
                .unwrap();
        }
        self.noise_level = noise_level;
    }
}

impl Debug for BoolFhe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BoolFhe: noise_level: {:?} {:?}",
            self.noise_level,
            DebugLweCiphertextWrapper(&self.context.client_key, self.ct.as_view())
        )
    }
}

struct DebugLweCiphertextWrapper<'a>(
    &'a shortint::ClientKey,
    lwe_ciphertext::LweCiphertextView<'a, u64>,
);

impl Debug for DebugLweCiphertextWrapper<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let plaintext: Plaintext<u64> =
            lwe_encryption::decrypt_lwe_ciphertext(&self.0.lwe_secret_key, &self.1);
        let decoded = BoolFhe::decode(plaintext);
        let noise = plaintext.0.wrapping_sub(BoolFhe::encode(decoded).0);
        write!(
            f,
            "{}\nplaintext: {:64b}\nnoise:     {:64b}",
            decoded, plaintext.0, noise
        )
    }
}

impl Default for BoolFhe {
    fn default() -> Self {
        BOOL_FHE_DEFAULT.get().expect("default set").clone()
    }
}

impl BitXorAssign<&BoolFhe> for BoolFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        let self_before = if PLAIN_CHECK {
            Some(self.clone())
        } else {
            None
        };

        lwe_linear_algebra::lwe_ciphertext_add_assign(&mut self.ct, &rhs.ct);

        if PLAIN_CHECK {
            let self_plain =
                fhe_decrypt_bool(&self.context.client_key, self_before.as_ref().unwrap());
            let rhs_plain = fhe_decrypt_bool(&self.context.client_key, rhs);
            let res_plain = fhe_decrypt_bool(&self.context.client_key, self);
            assert_eq!(
                self_plain ^ rhs_plain,
                res_plain,
                "xor lhs: {:?}, \nrhs: {:?}, \nres: {:?}",
                self_before.as_ref().unwrap(),
                rhs,
                self
            );
        }

        self.set_noise_level(self.noise_level + rhs.noise_level);
    }
}

impl BitXor for BoolFhe {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct BoolByteFhe([BoolFhe; 8]);

impl BoolByteFhe {
    pub fn trivial(val: u8, context: FheContext) -> Self {
        let mut byte = BoolByteFhe::default();
        for i in 0..8 {
            byte[i] = BoolFhe::trivial(0 != (val & (0x80 >> i)), context.clone());
        }
        byte
    }

    pub fn shl_assign_1(&mut self) -> BoolFhe {
        let ret = mem::take(&mut self.0[0]);
        self.shl_assign(1);
        ret
    }

    pub fn bits(&self) -> impl Iterator<Item = &BoolFhe> + '_ {
        self.0.iter()
    }

    pub fn bits_mut(&mut self) -> impl Iterator<Item = &mut BoolFhe> + '_ {
        self.0.iter_mut()
    }

    pub fn bootstrap_from_int_byte(int_byte: &IntByteFhe) -> Self {
        let context = &int_byte.context;

        let bit_cts =
            context
                .wopbs_key
                .extract_bits(DeltaLog(64 - 8), &int_byte.ct, ExtractedBitsCount(8));

        let bool_fhe_array = bit_cts
            .iter()
            .map(|bit_ct| {
                let start = Instant::now();
                let data = bit_ct.into_container().to_vec();
                println!("copy bit data {:?}", start.elapsed());

                BoolFhe::new(
                    LweCiphertextOwned::create_from(
                        data,
                        LweCiphertextCreationMetadata {
                            ciphertext_modulus: CiphertextModulus::new_native(),
                        },
                    ),
                    context.clone(),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("array length 8");

        Self(bool_fhe_array)
    }
}

impl Index<usize> for BoolByteFhe {
    type Output = BoolFhe;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for BoolByteFhe {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl ShlAssign<usize> for BoolByteFhe {
    fn shl_assign(&mut self, rhs: usize) {
        super::shl_array(&mut self.0, rhs);
    }
}

impl BitXorAssign<&BoolByteFhe> for BoolByteFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .par_bridge()
            .for_each(|(b, rhs_b)| {
                *b ^= rhs_b;
            });
    }
}

impl BitXor for BoolByteFhe {
    type Output = BoolByteFhe;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
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

impl Debug for IntByteFhe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntByteFhe").field("fhe", &self.ct).finish()
    }
}

impl Default for IntByteFhe {
    fn default() -> Self {
        INT_BYTE_FHE_DEFAULT.get().expect("default set").clone()
    }
}

impl IntByteFhe {
    pub fn bootstrap_from_bool_byte(bool_byte: &BoolByteFhe, lut: &ShortintWopbsLUT) -> Self {
        assert_eq!(lut.as_ref().output_ciphertext_count(), CiphertextCount(1));
        let context = &bool_byte.bits().next().unwrap().context;

        let lwe_size = bool_byte.bits().next().unwrap().ct.lwe_size();

        let bit_cts = bool_byte.bits().map(|bit| bit.ct.as_view());
        let start = Instant::now();
        let bits_data: Vec<u64> = bit_cts
            .flat_map(|bit_ct| bit_ct.into_container().iter().copied())
            .collect();
        println!("copy bits data {:?}", start.elapsed());

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

/// State of 4 rows each of 4 bytes
#[derive(Debug, Default)]
pub struct StateFhe([WordFhe; 4]);

impl StateFhe {
    pub fn from_array(block: [BoolByteFhe; 16]) -> Self {
        let mut this = Self::default();
        for (i, byte) in block.into_iter().enumerate() {
            this[i % 4][i / 4] = byte;
        }
        this
    }

    pub fn into_array(self) -> [BoolByteFhe; 16] {
        let mut array: [BoolByteFhe; 16] = Default::default();
        for (i, row) in self.0.into_iter().enumerate() {
            for (j, byte) in row.0.into_iter().enumerate() {
                array[i + j * 4] = byte;
            }
        }
        array
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut BoolByteFhe> {
        self.0.iter_mut().flat_map(|w| w.0.iter_mut())
    }

    pub fn rows_mut(&mut self) -> impl Iterator<Item = &mut WordFhe> {
        self.0.iter_mut()
    }

    pub fn columns(&self) -> impl Iterator<Item = ColumnViewFhe<'_>> {
        (0..4).map(|j| ColumnViewFhe(j, &self.0))
    }

    pub fn column(&self, j: usize) -> ColumnViewFhe<'_> {
        ColumnViewFhe(j, &self.0)
    }

    pub fn column_mut(&mut self, j: usize) -> ColumnViewMutFhe<'_> {
        ColumnViewMutFhe(j, &mut self.0)
    }
}

impl Index<usize> for StateFhe {
    type Output = WordFhe;

    fn index(&self, row: usize) -> &Self::Output {
        &self.0[row]
    }
}

impl IndexMut<usize> for StateFhe {
    fn index_mut(&mut self, row: usize) -> &mut Self::Output {
        &mut self.0[row]
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ColumnViewFhe<'a>(usize, &'a [WordFhe; 4]);

impl ColumnViewFhe<'_> {
    pub fn bytes(&self) -> impl Iterator<Item = &BoolByteFhe> + '_ {
        (0..4).map(|i| &self.1[i][self.0])
    }

    pub fn clone_to_word(&self) -> WordFhe {
        let mut col: WordFhe = Default::default();
        for i in 0..4 {
            col.0[i] = self.1[i][self.0].clone();
        }
        col
    }
}

impl Index<usize> for ColumnViewFhe<'_> {
    type Output = BoolByteFhe;

    fn index(&self, row: usize) -> &Self::Output {
        &self.1[row][self.0]
    }
}

#[derive(Debug)]
pub struct ColumnViewMutFhe<'a>(usize, &'a mut [WordFhe; 4]);

impl ColumnViewMutFhe<'_> {
    pub fn bytes(&self) -> impl Iterator<Item = &BoolByteFhe> + '_ {
        (0..4).map(|i| &self.1[i][self.0])
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &'_ mut BoolByteFhe> + '_ {
        self.1.iter_mut().map(|row| &mut row[self.0])
    }

    pub fn bitxor_assign(&mut self, rhs: &WordFhe) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .par_bridge()
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
    }

    pub fn assign(&mut self, rhs: WordFhe) {
        for (i, byte) in rhs.into_bytes().enumerate() {
            self.1[i][self.0] = byte;
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WordFhe(pub [BoolByteFhe; 4]);

impl WordFhe {
    pub fn bytes(&self) -> impl Iterator<Item = &BoolByteFhe> + '_ {
        self.0.iter()
    }

    pub fn into_bytes(self) -> impl Iterator<Item = BoolByteFhe> {
        self.0.into_iter()
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut BoolByteFhe> {
        self.0.iter_mut()
    }

    pub fn rotate_left(mut self, mid: usize) -> Self {
        self.rotate_left_assign(mid);
        self
    }

    pub fn rotate_left_assign(&mut self, mid: usize) {
        self.0.rotate_left(mid);
    }
}

impl Index<usize> for WordFhe {
    type Output = BoolByteFhe;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for WordFhe {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl BitXorAssign<&Self> for WordFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .par_bridge()
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
    }
}

impl BitXor<&WordFhe> for WordFhe {
    type Output = WordFhe;

    fn bitxor(mut self, rhs: &Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

pub fn fhe_encrypt_word_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    context: &FheContext,
    array: &[Word; N],
) -> [WordFhe; N] {
    array
        .par_iter()
        .map(|word| WordFhe(fhe_encrypt_bool_byte_array(client_key, context, &word.0)))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_encrypt_byte_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    context: &FheContext,
    array: &[u8; N],
) -> [BoolByteFhe; N] {
    array
        .par_iter()
        .map(|&byte| fhe_encrypt_byte(client_key, context, byte.into()))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_encrypt_bool_byte_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    context: &FheContext,
    array: &[BoolByte; N],
) -> [BoolByteFhe; N] {
    array
        .par_iter()
        .map(|&byte| fhe_encrypt_byte(client_key, context, byte))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_encrypt_byte(
    client_key: &shortint::client_key::ClientKey,
    context: &FheContext,
    byte: BoolByte,
) -> BoolByteFhe {
    BoolByteFhe(
        byte.0
            .par_iter()
            .map(|b| fhe_encrypt_bool(client_key, context, *b))
            .collect::<Vec<_>>()
            .try_into()
            .expect("constant length"),
    )
}

pub fn fhe_encrypt_bool(
    client_key: &shortint::client_key::ClientKey,
    context: &FheContext,
    b: bool,
) -> BoolFhe {
    let (encryption_lwe_sk, encryption_noise_distribution) = (
        &client_key.lwe_secret_key,
        client_key.parameters.lwe_noise_distribution(),
    );

    let ct = ShortintEngine::with_thread_local_mut(|engine| {
        lwe_encryption::allocate_and_encrypt_new_lwe_ciphertext(
            &encryption_lwe_sk,
            BoolFhe::encode(b),
            encryption_noise_distribution,
            client_key.parameters.ciphertext_modulus(),
            &mut engine.encryption_generator,
        )
    });

    BoolFhe::new(ct, context.clone())
}

pub fn fhe_decrypt_word_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    array: &[WordFhe; N],
) -> [Word; N] {
    array
        .par_iter()
        .map(|word| Word(fhe_decrypt_bool_byte_array(client_key, &word.0)))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_decrypt_byte_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    array: &[BoolByteFhe; N],
) -> [u8; N] {
    array
        .par_iter()
        .map(|byte| fhe_decrypt_byte(client_key, byte).into())
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_decrypt_bool_byte_array<const N: usize>(
    client_key: &shortint::client_key::ClientKey,
    array: &[BoolByteFhe; N],
) -> [BoolByte; N] {
    array
        .par_iter()
        .map(|byte| fhe_decrypt_byte(client_key, byte))
        .collect::<Vec<_>>()
        .try_into()
        .expect("constant length")
}

pub fn fhe_decrypt_byte(
    client_key: &shortint::client_key::ClientKey,
    byte: &BoolByteFhe,
) -> BoolByte {
    BoolByte(
        byte.0
            .par_iter()
            .map(|b| fhe_decrypt_bool(client_key, b))
            .collect::<Vec<_>>()
            .try_into()
            .expect("constant length"),
    )
}

pub fn fhe_decrypt_bool(client_key: &shortint::client_key::ClientKey, b: &BoolFhe) -> bool {
    let lwe_decryption_key = &client_key.lwe_secret_key;
    let encoding = lwe_encryption::decrypt_lwe_ciphertext(&lwe_decryption_key, &b.ct);
    BoolFhe::decode(encoding)
}

pub fn fhe_decrypt_state(context: &FheContext, state_fhe: StateFhe) -> State {
    let array = fhe_decrypt_byte_array(&context.client_key, &state_fhe.into_array());
    State::from_array(&array)
}

pub fn fhe_encrypt_state(context: &FheContext, state: State) -> StateFhe {
    let array = fhe_encrypt_byte_array(&context.client_key, context, &state.to_array());
    StateFhe::from_array(array)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{Arc, LazyLock};
    use std::time::Instant;
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::wopbs::WopbsKey;
    use tfhe::shortint::{
        CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, ShortintParameterSet,
        WopbsParameters,
    };

    fn params() -> ShortintParameterSet {
        let wopbs_params = WopbsParameters {
            lwe_dimension: LweDimension(750),
            glwe_dimension: GlweDimension(2),
            polynomial_size: PolynomialSize(1024),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                1.5140301927925663e-05,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                0.00000000000000022148688116005568513645324585951,
            )),
            pbs_base_log: DecompositionBaseLog(5),
            pbs_level: DecompositionLevelCount(8),
            ks_level: DecompositionLevelCount(15),
            ks_base_log: DecompositionBaseLog(1),
            pfks_level: DecompositionLevelCount(4),
            pfks_base_log: DecompositionBaseLog(10),
            pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                0.00000000000000022148688116005568513645324585951,
            )),
            cbs_level: DecompositionLevelCount(7),
            cbs_base_log: DecompositionBaseLog(4),
            message_modulus: MessageModulus(256),
            carry_modulus: CarryModulus(1),
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Small,
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
            max_noise_level: MaxNoiseLevel::new(10),
            log2_p_fail: -64.074,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
    }

    static KEYS: LazyLock<(Arc<shortint::ClientKey>, FheContext)> = LazyLock::new(|| keys_impl());

    fn keys_impl() -> (Arc<shortint::ClientKey>, FheContext) {
        let (client_key, server_key) = shortint::gen_keys(params());

        // println!("server key: {:#?}", server_key);

        let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&client_key, &server_key);

        let context = FheContext {
            client_key: client_key.clone().into(),
            server_key: server_key.into(),
            wopbs_key: wops_key.into(),
        };

        BOOL_FHE_DEFAULT
            .set(BoolFhe::trivial(false, context.clone()))
            .expect("only set once");

        INT_BYTE_FHE_DEFAULT
            .set(IntByteFhe::new(
                context.server_key.create_trivial(0),
                context.clone(),
            ))
            .expect("only set once");

        (context.client_key.clone(), context)
    }

    #[test]
    fn test_bool_fhe_encode() {
        assert_eq!(BoolFhe::encode(false), Plaintext(0));
        assert_eq!(BoolFhe::encode(true), Plaintext(1 << 63));
    }

    #[test]
    fn test_bool_fhe_decode() {
        assert_eq!(BoolFhe::decode(Plaintext(0)), false);
        assert_eq!(BoolFhe::decode(Plaintext(1)), false);
        assert_eq!(BoolFhe::decode(Plaintext(u64::MAX)), false);
        assert_eq!(BoolFhe::decode(Plaintext(1 << 63)), true);
        assert_eq!(BoolFhe::decode(Plaintext((1 << 63) - 1)), true);
        assert_eq!(BoolFhe::decode(Plaintext((1 << 63) + 1)), true);
    }

    #[test]
    fn test_pbssub_wop_shortint_bool_fhe() {
        let (client_key, context) = KEYS.clone();

        let mut b1 = fhe_encrypt_bool(&client_key, &context, false);
        let b2 = fhe_encrypt_bool(&client_key, &context, true);

        assert_eq!(fhe_decrypt_bool(&client_key, &b1), false);
        assert_eq!(fhe_decrypt_bool(&client_key, &b2), true);

        assert_eq!(
            fhe_decrypt_bool(&client_key, &(b1.clone() ^ b2.clone())),
            true
        );
        assert_eq!(
            fhe_decrypt_bool(&client_key, &(b1.clone() ^ b1.clone())),
            false
        );
        assert_eq!(
            fhe_decrypt_bool(&client_key, &(b2.clone() ^ b2.clone())),
            false
        );

        // default/trivial
        assert_eq!(fhe_decrypt_bool(&client_key, &BoolFhe::default()), false);
        assert_eq!(
            fhe_decrypt_bool(&client_key, &(b2.clone() ^ BoolFhe::default())),
            true
        );
        assert_eq!(
            fhe_decrypt_bool(&client_key, &BoolFhe::trivial(false, context.clone())),
            false
        );
        assert_eq!(
            fhe_decrypt_bool(&client_key, &BoolFhe::trivial(true, context.clone())),
            true
        );
    }

    #[test]
    fn test_pbssub_wop_shortint_bool_byte_fhe() {
        let (client_key, context) = KEYS.clone();

        // default/trivial
        assert_eq!(
            u8::from(fhe_decrypt_byte(&client_key, &BoolByteFhe::default())),
            0
        );
        assert_eq!(
            u8::from(fhe_decrypt_byte(
                &client_key,
                &BoolByteFhe::trivial(123, context.clone())
            )),
            123
        );
    }

    #[test]
    fn test_pbssub_wop_shortint_word_fhe() {
        let (client_key, context) = KEYS.clone();

        // default/trivial
        assert_eq!(
            fhe_decrypt_byte_array(&client_key, &WordFhe::default().0),
            [0, 0, 0, 0]
        );
    }

    #[test]
    fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe() {
        let (client_key, context) = KEYS.clone();

        let bool_byte = BoolByte::from(0b10110101);
        let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);

        let lut = IntByteFhe::generate_lookup_table(&context, |val| val);
        let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);

        let decrypted = client_key.decrypt_without_padding(&int_byte_fhe.ct);
        assert_eq!(decrypted, 0b10110101);
    }

    #[test]
    fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe2() {
        let (client_key, context) = KEYS.clone();

        let bool_byte = BoolByte::from(0b10110101);
        let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);

        let bool_byte2 = BoolByte::from(0b01100110);
        let bool_byte_fhe2 = fhe_encrypt_byte(&client_key, &context, bool_byte2);

        let bool_byte_fhe = bool_byte_fhe ^ bool_byte_fhe2.clone();

        let lut = IntByteFhe::generate_lookup_table(&context, |val| val);
        let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);

        let decrypted_int = client_key.decrypt_without_padding(&int_byte_fhe.ct) as u8;
        let decrypted_bool = u8::from(fhe_decrypt_byte(&client_key, &bool_byte_fhe));
        assert_eq!(decrypted_int, decrypted_bool);
    }

    #[test]
    fn test_pbssub_wop_shortint_int_byte_boostrap_from_bool_byte_fhe_lut() {
        let (client_key, context) = KEYS.clone();

        let bool_byte = BoolByte::from(0b10110101);
        let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);

        let lut = IntByteFhe::generate_lookup_table(&context, |val| val + 3);
        let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe, &lut);

        let decrypted = client_key.decrypt_without_padding(&int_byte_fhe.ct);
        assert_eq!(decrypted, 0b10110101 + 3);
    }

    #[test]
    fn test_pbssub_wop_shortint_bool_byte_boostrap_from_int_byte_fhe() {
        let (client_key, context) = KEYS.clone();

        let int_byte_fhe = IntByteFhe::new(client_key.encrypt_without_padding(0b10110101), context);
        let bool_byte_fhe = BoolByteFhe::bootstrap_from_int_byte(&int_byte_fhe);

        let bool_byte = fhe_decrypt_byte(&client_key, &bool_byte_fhe);
        assert_eq!(u8::from(bool_byte), 0b10110101);
    }

    #[test]
    fn test_pbssub_wob_shortint_perf() {
        let start = Instant::now();
        let (client_key, context) = KEYS.clone();
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();
        let mut b1 = client_key.encrypt_without_padding(1);
        let b2 = client_key.encrypt_without_padding(3);
        println!(
            "data encrypted: {:?}, dim: {}",
            start.elapsed(),
            b2.ct.data.len()
        );

        let start = Instant::now();
        context.server_key.unchecked_add_assign(&mut b1, &b2);
        println!("add elapsed: {:?}", start.elapsed());

        let lut = context
            .wopbs_key
            .generate_lut_without_padding(&b1, |a| a)
            .into();
        let start = Instant::now();
        _ = context
            .wopbs_key
            .programmable_bootstrapping_without_padding(&b1, &lut);
        println!("bootstrap elapsed: {:?}", start.elapsed());
    }

    #[test]
    fn test_pbssub_wob_shortint_extract_bits() {
        let start = Instant::now();
        let (client_key, context) = KEYS.clone();
        println!("keys generated: {:?}", start.elapsed());

        let cte1 = client_key.encrypt_without_padding(0b0110100);

        let start = Instant::now();
        let delta = (1u64 << (64 - 8));
        let delta_log = DeltaLog(delta.ilog2() as usize);
        let bit_cts = context
            .wopbs_key
            .extract_bits(delta_log, &cte1, ExtractedBitsCount(8));
        println!("bootstrap elapsed: {:?}", start.elapsed());

        // let lwe_decryption_key = client_key.glwe_secret_key.as_lwe_secret_key();
        let lwe_decryption_key = &client_key.lwe_secret_key;
        for (i, bit_ct) in bit_cts.iter().enumerate() {
            let decrypted = lwe_encryption::decrypt_lwe_ciphertext(&lwe_decryption_key, &bit_ct);
            let decoded = decrypted.0 >> (64 - 8);
            println!("bit {}: {:b}", i, decoded);
        }
    }
}

// todo allan use borrowed types for list ciphertexts?
// todo allan test non-trivial lut
