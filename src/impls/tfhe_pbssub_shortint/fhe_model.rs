use crate::impls::tfhe_pbssub_shortint::model::{BoolByte, State, Word};
use crate::impls::tfhe_pbssub_shortint::{FheContext, BOOL_FHE_DEFAULT, INT_BYTE_FHE_DEFAULT};
use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::{Debug, Formatter};
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::{fmt, mem};
use tfhe::core_crypto::entities::Plaintext;
use tfhe::core_crypto::prelude::lwe_encryption;
use tfhe::shortint;
use tfhe::shortint::encoding::{PaddingBit, ShortintEncoding};
use tfhe::shortint::server_key::LookupTableOwned;
use tfhe::shortint::{encoding, ClientKey};

pub type BlockFhe = [BoolByteFhe; 16];

#[derive(Clone)]
pub struct BoolFhe {
    pub ct: shortint::ciphertext::Ciphertext,
    pub context: FheContext,
}

impl BoolFhe {
    pub fn new(fhe: shortint::ciphertext::Ciphertext, context: FheContext) -> Self {
        Self { ct: fhe, context }
    }
}

impl Debug for BoolFhe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BoolFhe: {:?}",
            DebugShortintWrapper(&self.context.client_key, &self.ct)
        )
    }
}

struct DebugShortintWrapper<'a>(&'a shortint::ClientKey, &'a shortint::Ciphertext);

impl Debug for DebugShortintWrapper<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let plaintext: Plaintext<u64> = lwe_encryption::decrypt_lwe_ciphertext(
            &self.0.glwe_secret_key.as_lwe_secret_key(),
            &self.1.ct,
        );
        let decoded = self.0.decrypt_message_and_carry(&self.1);

        let delta = encoding::compute_delta(
            self.0.parameters.ciphertext_modulus(),
            self.0.parameters.message_modulus(),
            self.0.parameters.carry_modulus(),
            PaddingBit::Yes,
        );

        let noise = (plaintext.0 as i64 - delta as i64 * decoded as i64);
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
        self.context
            .server_key
            .unchecked_add_assign(&mut self.ct, &rhs.ct);
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

        let mut res = Self::default();
        for (index, bit) in res.bits_mut().enumerate() {
            let lut = context
                .server_key
                .generate_lookup_table(|unscaled| (unscaled >> (8 - index - 1)) & 1);
            *bit = BoolFhe::new(
                context.server_key.apply_lookup_table(&int_byte.ct, &lut),
                context.clone(),
            );
        }
        res
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
    pub fn bootstrap_from_bool_byte(bool_byte: &BoolByteFhe) -> Self {
        let mut res = Self::default();
        let context = &res.context;

        for (index, bit) in bool_byte.bits().enumerate() {
            // todo move to static lazy
            let lut = context
                .server_key
                .generate_lookup_table(|unscaled| (unscaled & 1) << (8 - index - 1));
            let scaled = context.server_key.apply_lookup_table(&bit.ct, &lut);
            context
                .server_key
                .unchecked_add_assign(&mut res.ct, &scaled);
        }
        res
    }

    pub fn apply_lookup_table_assign(&mut self, acc: &LookupTableOwned) {
        self.context
            .server_key
            .apply_lookup_table_assign(&mut self.ct, acc);
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

impl BitXorAssign for WordFhe {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .par_bridge()
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
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
    BoolFhe::new(client_key.encrypt(b.into()), context.clone())
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
    let val = client_key.decrypt(&b.ct) & 1;
    (val & 1) != 0
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
    use std::io::stdout;
    use std::sync::Arc;
    use std::time::Instant;
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::parameters::{
        V0_11_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    };
    use tfhe::shortint::{CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus};

    // 8 bit
    const PARAMS8: ClassicPBSParameters = ClassicPBSParameters {
        lwe_dimension: LweDimension(1091),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.038278019865525e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(6),
        pbs_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(11),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -64.074,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

    fn keys() -> (Arc<shortint::ClientKey>, FheContext) {
        keys_with_params(PARAMS8)
    }

    fn keys_with_params(params: ClassicPBSParameters) -> (Arc<shortint::ClientKey>, FheContext) {
        let (client_key, server_key) = shortint::gen_keys(params);

        let context = FheContext {
            client_key: client_key.clone().into(),
            server_key: server_key.into(),
        };

        BOOL_FHE_DEFAULT
            .set(BoolFhe::new(
                context.server_key.create_trivial(0),
                context.clone(),
            ))
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
    fn test_pbssub_shortint_bool_fhe() {
        let (client_key, context) = keys();

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
    }

    #[test]
    fn test_pbssub_shortint_int_byte_boostrap_from_bool_byte_fhe() {
        let (client_key, context) = keys();

        let bool_byte = BoolByte::from(0b10110101);
        let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);
        let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe);

        let decrypted = client_key.decrypt(&int_byte_fhe.ct);
        assert_eq!(decrypted, 0b10110101);
    }

    #[test]
    fn test_pbssub_shortint_int_byte_boostrap_from_bool_byte_fhe2() {
        let (client_key, context) = keys();

        let bool_byte = BoolByte::from(0b10110101);
        let bool_byte_fhe = fhe_encrypt_byte(&client_key, &context, bool_byte);

        let bool_byte2 = BoolByte::from(0b01100110);
        let bool_byte_fhe2 = fhe_encrypt_byte(&client_key, &context, bool_byte2);

        let bool_byte_fhe = bool_byte_fhe ^ bool_byte_fhe2.clone();

        let int_byte_fhe = IntByteFhe::bootstrap_from_bool_byte(&bool_byte_fhe);

        let decrypted_int = client_key.decrypt(&int_byte_fhe.ct) as u8;
        let decrypted_bool = u8::from(fhe_decrypt_byte(&client_key, &bool_byte_fhe));
        assert_eq!(decrypted_int, decrypted_bool);
    }

    #[test]
    fn test_pbssub_shortint_bool_byte_boostrap_from_int_byte_fhe() {
        let (client_key, context) = keys();

        let int_byte_fhe = IntByteFhe::new(client_key.encrypt(0b10110101), context);
        let bool_byte_fhe = BoolByteFhe::bootstrap_from_int_byte(&int_byte_fhe);

        let bool_byte = fhe_decrypt_byte(&client_key, &bool_byte_fhe);
        assert_eq!(u8::from(bool_byte), 0b10110101);
    }

    #[test]
    fn test_pbssub_shortint_perf() {
        let start = Instant::now();
        let (client_key, context) = keys();
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();
        let mut b1 = client_key.encrypt(1);
        let b2 = client_key.encrypt(3);
        println!(
            "data encrypted: {:?}, dim: {}",
            start.elapsed(),
            b2.ct.data.len()
        );

        let start = Instant::now();
        context.server_key.unchecked_add_assign(&mut b1, &b2);
        println!("add elapsed: {:?}", start.elapsed());

        let start = Instant::now();
        context.server_key.message_extract_assign(&mut b1);
        println!("bootstrap elapsed: {:?}", start.elapsed());
    }

    #[test]
    fn test_pbssub_shortint_bootstrap_negacyclic() {
        let start = Instant::now();
        let (client_key, context) = keys();
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();
        let mut b1 = client_key.encrypt(128);
        let b2 = client_key.encrypt(128);
        context.server_key.unchecked_add_assign(&mut b1, &b2);

        let sum_raw = client_key.decrypt_message_and_carry(&b1);
        println!("sumraw {}", sum_raw);
        let sum = client_key.decrypt(&b1);
        println!("sum {}", sum);

        let lut = context.server_key.generate_lookup_table(|a| a & 1);
    }

    #[test]
    fn test_shortint_noise_scalar() {
        const PARAMS: ClassicPBSParameters = ClassicPBSParameters {
            lwe_dimension: LweDimension(1091),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(32768),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                3.038278019865525e-08,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.168404344971009e-19,
            )),
            pbs_base_log: DecompositionBaseLog(11),
            pbs_level: DecompositionLevelCount(3),
            ks_base_log: DecompositionBaseLog(3),
            ks_level: DecompositionLevelCount(8),
            message_modulus: MessageModulus(256),
            carry_modulus: CarryModulus(1),
            max_noise_level: MaxNoiseLevel::new(500),
            log2_p_fail: -64.074,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
        };

        let start = Instant::now();
        let (client_key, context) = keys_with_params(PARAMS);
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();

        for i in 0..1000000 {
            let scalar = 85;
            let mut b1 = client_key.encrypt(3);
            println!("before: {:?}", DebugShortintWrapper(&client_key, &b1));
            context
                .server_key
                .unchecked_scalar_mul_assign(&mut b1, scalar);
            println!("after: {:?}", DebugShortintWrapper(&client_key, &b1));

            let decrypted = client_key.decrypt(&b1);
            assert_eq!(decrypted, (scalar * 3) as u64);
            println!("check {}", i);
        }
    }

    #[test]
    fn test_shortint_noise_sum() {
        const PARAMS: ClassicPBSParameters = ClassicPBSParameters {
            lwe_dimension: LweDimension(1091),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(32768),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                3.038278019865525e-08,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.168404344971009e-19,
            )),
            pbs_base_log: DecompositionBaseLog(11),
            pbs_level: DecompositionLevelCount(3),
            ks_base_log: DecompositionBaseLog(3),
            ks_level: DecompositionLevelCount(8),
            message_modulus: MessageModulus(256),
            carry_modulus: CarryModulus(1),
            max_noise_level: MaxNoiseLevel::new(500),
            log2_p_fail: -64.074,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
        };

        let start = Instant::now();
        let (client_key, context) = keys_with_params(PARAMS);
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();

        for i in 0..1000000 {
            let mut b1 = client_key.encrypt(3);
            println!("before: {:?}", DebugShortintWrapper(&client_key, &b1));
            let b2 = client_key.encrypt(1);
            for _ in 0..250 {
                context.server_key.unchecked_add_assign(&mut b1, &b2);
            }
            println!("after: {:?}", DebugShortintWrapper(&client_key, &b1));

            let decrypted = client_key.decrypt(&b1);
            assert_eq!(decrypted, 253);
            println!("check {}", i);
        }
    }
}
