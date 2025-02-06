mod fhe_model;
mod model;

use crate::impls::tfhe_pbssub_wop_shortint::fhe_model::{
    fhe_decrypt_byte, fhe_decrypt_word_array, fhe_encrypt_byte, fhe_encrypt_word_array, BlockFhe,
    BoolByteFhe, BoolFhe, IntByteFhe, StateFhe, WordFhe,
};
use crate::impls::tfhe_pbssub_wop_shortint::model::{BoolByte, State, Word};
use crate::{Block, Key};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelBridge};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::fmt::{Debug, Formatter};
use std::ops::{BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use std::{array, mem};
use tfhe::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweDimension, PolynomialSize, StandardDev,
};
use tfhe::shortint;
use tfhe::shortint::wopbs::{ShortintWopbsLUT, WopbsKey};
use tfhe::shortint::{
    CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus,
    ShortintParameterSet, WopbsParameters,
};

static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

static RC: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

static SBOX_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();

fn substitute_part1(byte: &BoolByteFhe) -> IntByteFhe {
    let context = &byte.bits().next().unwrap().context;

    let lut = SBOX_LUT.get_or_init(|| {
        IntByteFhe::generate_lookup_table(context, |byte| SBOX[byte as usize].into())
    });
    let start = Instant::now();
    let int_byte = IntByteFhe::bootstrap_from_bool_byte(&byte, &lut);
    println!("boot int {:?}", start.elapsed());

    int_byte
}

fn substitute_part2(byte: IntByteFhe) -> BoolByteFhe {
    let start = Instant::now();
    let bool_byte = BoolByteFhe::bootstrap_from_int_byte(&byte);
    println!("boot bools {:?}", start.elapsed());

    bool_byte
}

fn substitute(byte: &BoolByteFhe) -> BoolByteFhe {
    let int_byte = substitute_part1(byte);
    substitute_part2(int_byte)
}

fn substitute_plain(byte: BoolByte) -> BoolByte {
    SBOX[u8::from(byte) as usize].into()
}

fn xor_state(state: &mut StateFhe, key: &[WordFhe; 4]) {
    for (j, word) in key.iter().enumerate() {
        state.column_mut(j).bitxor_assign(word);
    }
}

fn sub_bytes(state: &mut StateFhe) {
    state
        .bytes_mut()
        .par_bridge()
        .map(|state_byte| (substitute_part1(state_byte), state_byte))
        .for_each(|(byte, state_byte)| {
            *state_byte = substitute_part2(byte);
        })
}

fn shift_rows(state: &mut StateFhe) {
    for (i, row) in state.rows_mut().enumerate() {
        row.rotate_left_assign(i);
    }
}

/// Multiplication in F_2[X]/(X^8 + X^4 + X^3 + X + 1)
fn gf_256_mul(context: &FheContext, a: &BoolByteFhe, mut b: u8) -> BoolByteFhe {
    let mut a = a.clone();
    let mut res = BoolByteFhe::default();
    for _ in 0..8 {
        if b & 1 == 1 {
            res ^= &a;
        }
        let reduce_x8 = a.shl_assign_1();

        a[3] ^= &reduce_x8;
        a[4] ^= &reduce_x8;
        a[6] ^= &reduce_x8;
        a[7] ^= &reduce_x8;

        b >>= 1;
    }

    res
}

/// Multiplication in F_2[X]/(X^8 + X^4 + X^3 + X + 1)
fn gf_256_mul_plain(context: &FheContext, a: &BoolByteFhe, mut b: u8) -> BoolByteFhe {
    let a = fhe_model::fhe_decrypt_byte(&context.client_key, a);
    let mut a = u8::from(a);

    let mut res = 0u8;
    for _ in 0..8 {
        if b & 1 == 1 {
            res ^= a
        }

        let mut a_bits = BoolByte::from(a);

        let reduce_x8 = a_bits.shl_assign_1();

        a_bits[3] ^= reduce_x8;
        a_bits[4] ^= reduce_x8;
        a_bits[6] ^= reduce_x8;
        a_bits[7] ^= reduce_x8;

        a = u8::from(a_bits);

        b >>= 1;
    }

    fhe_model::fhe_encrypt_byte(&context.client_key, context, res.into())
}

fn mix_columns(context: &FheContext, state: &mut StateFhe) {
    let new_columns: [WordFhe; 4] = collect_array(
        state
            .columns()
            .collect::<Vec<_>>()
            .par_iter()
            .map(|column| {
                WordFhe(collect_array((0..4).into_par_iter().map(|i| {
                    gf_256_mul(context, &column[i], 2)
                        ^ gf_256_mul(context, &column[(i - 1) % 4], 1)
                        ^ gf_256_mul(context, &column[(i - 2) % 4], 1)
                        ^ gf_256_mul(context, &column[(i - 3) % 4], 3)
                })))
            }),
    );

    for (j, column) in new_columns.into_iter().enumerate() {
        state.column_mut(j).assign(column);
    }
}

pub fn encrypt_block(
    context: &FheContext,
    expanded_key_fhe: &[WordFhe; 44],
    block: BlockFhe,
    rounds: usize,
) -> BlockFhe {
    let mut state_fhe = StateFhe::from_array(block);

    xor_state(
        &mut state_fhe,
        expanded_key_fhe[0..4].try_into().expect("array length 4"),
    );

    for i in 1..rounds {
        println!("starting round");
        println!("sub_bytes");
        sub_bytes(&mut state_fhe);
        println!("shift_rows");
        shift_rows(&mut state_fhe);
        println!("mix_columns");
        mix_columns(context, &mut state_fhe);
        println!("xor_state");
        xor_state(
            &mut state_fhe,
            expanded_key_fhe[i * 4..(i + 1) * 4]
                .try_into()
                .expect("array length 4"),
        );
    }

    println!("starting last round");
    println!("sub_bytes");
    sub_bytes(&mut state_fhe);
    println!("shift_rows");
    shift_rows(&mut state_fhe);
    println!("xor_state");
    xor_state(
        &mut state_fhe,
        expanded_key_fhe[40..44].try_into().expect("array length 4"),
    );

    state_fhe.into_array()
}

pub fn key_schedule(context: &FheContext, key_slice: &[BoolByteFhe; 16]) -> [WordFhe; 44] {
    let mut key: [WordFhe; 4] = Default::default();
    let mut expanded_key: [WordFhe; 44] = array::from_fn(|_| WordFhe::default());

    for i in 0..4 {
        for j in 0..4 {
            expanded_key[i][j] = key_slice[i * 4 + j].clone();
        }
    }

    // expanded_key[..4].clone_from_slice(&key);

    for i in 4..44 {
        if i % 4 == 0 {
            expanded_key[i] =
                expanded_key[i - 4].clone() ^ &sub_word(expanded_key[i - 1].clone().rotate_left(1));
            expanded_key[i][0] ^= &BoolByteFhe::trivial(RC[i / 4], context.clone());
        } else {
            expanded_key[i] = expanded_key[i - 4].clone() ^ &expanded_key[i - 1];
        }

        // bootstrap all words to control noise level
        if i % 4 == 3 {
            expanded_key[i - 3..=i].par_iter_mut().for_each(|word| {
                boot_word(word);
            });
        }
    }

    // static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();
    //
    // expanded_key
    //     .iter_mut()
    //     .flat_map(|word| word.bytes_mut())
    //     .par_bridge()
    //     .for_each(|byte| {
    //         let lut = IDENTITY_LUT
    //             .get_or_init(|| IntByteFhe::generate_lookup_table(context, |byte| byte));
    //         *byte = BoolByteFhe::bootstrap_from_int_byte(&IntByteFhe::bootstrap_from_bool_byte(
    //             &byte, lut,
    //         ));
    //     });

    expanded_key
}

pub fn key_schedule_plain(key_slice: &Key) -> [Word; 44] {
    let mut key: [Word; 4] = Default::default();
    let mut expanded_key: [Word; 44] = [Word::zero(); 44];

    for i in 0..4 {
        for j in 0..4 {
            key[i][j] = key_slice[i * 4 + j].into();
        }
    }

    expanded_key[..4].copy_from_slice(&key);

    for i in 4..44 {
        if i % 4 == 0 {
            let mut rcon = Word::default();
            rcon[0] = RC[i / 4].into();
            expanded_key[i] =
                expanded_key[i - 4] ^ sub_word_plain(expanded_key[i - 1].rotate_left(1)) ^ rcon;
        } else {
            expanded_key[i] = expanded_key[i - 4] ^ expanded_key[i - 1];
        }
    }

    expanded_key
}

fn boot_word(word: &mut WordFhe) {
    word.bytes_mut().par_bridge().for_each(|byte| {
        *byte = boot_byte(byte);
    });
}

fn boot_byte(byte: &BoolByteFhe) -> BoolByteFhe {
    let context = &byte.bits().next().unwrap().context;

    static IDENTITY_LUT: OnceLock<ShortintWopbsLUT> = OnceLock::new();

    let lut = IDENTITY_LUT.get_or_init(|| IntByteFhe::generate_lookup_table(context, |byte| byte));
    let start = Instant::now();
    let int_byte = IntByteFhe::bootstrap_from_bool_byte(&byte, &lut);
    println!("boot int {:?}", start.elapsed());

    let start = Instant::now();
    let bool_byte = BoolByteFhe::bootstrap_from_int_byte(&int_byte);
    println!("boot bools {:?}", start.elapsed());

    bool_byte
}

fn sub_word(mut word: WordFhe) -> WordFhe {
    word.bytes_mut()
        .par_bridge()
        .map(|word_byte| (substitute_part1(word_byte), word_byte))
        .for_each(|(byte, word_byte)| {
            *word_byte = substitute_part2(byte);
        });

    word
}

fn sub_word_plain(mut word: Word) -> Word {
    word.bytes_mut().par_bridge().for_each(|byte| {
        *byte = substitute_plain(*byte);
    });
    word
}

static BOOL_FHE_DEFAULT: OnceLock<BoolFhe> = OnceLock::new();
static INT_BYTE_FHE_DEFAULT: OnceLock<IntByteFhe> = OnceLock::new();

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
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -64.074,
        ciphertext_modulus: wopbs_params.ciphertext_modulus,
        encryption_key_choice: wopbs_params.encryption_key_choice,
    };

    ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
}

pub fn encrypt_single_block(key: Key, block: Block, rounds: usize) -> Block {
    println!("start");

    let (client_key, server_key) = shortint::gen_keys(params());

    let wops_key = WopbsKey::new_wopbs_key_only_for_wopbs(&client_key, &server_key);

    let context = FheContext {
        client_key: client_key.into(),
        server_key: server_key.into(),
        wopbs_key: wops_key.into(),
    };

    println!("keys generated");

    BOOL_FHE_DEFAULT
        .set(BoolFhe::trivial(false, context.clone()))
        .expect("only set once");

    INT_BYTE_FHE_DEFAULT
        .set(IntByteFhe::new(
            context.server_key.create_trivial(0),
            context.clone(),
        ))
        .expect("only set once");

    let key_fhe = fhe_model::fhe_encrypt_byte_array(&context.client_key, &context, &key);
    let block_fhe = fhe_model::fhe_encrypt_byte_array(&context.client_key, &context, &block);

    println!("aes key and block encrypted");

    let start = Instant::now();

    let key_schedule_fhe = key_schedule(&context, &key_fhe);

    let key_schedule_plain = key_schedule_plain(&key);
    let key_schedule_decrypted = fhe_decrypt_word_array(&context.client_key, &key_schedule_fhe);
    if key_schedule_decrypted != key_schedule_plain {
        eprintln!("wrong key schedule encryption");
        panic!();
    }

    let key_schedule_fhe =
        fhe_encrypt_word_array(&context.client_key, &context, &key_schedule_plain);

    println!("key schedule created {:?}", start.elapsed());

    let encrypted = encrypt_block(&context, &key_schedule_fhe, block_fhe, rounds);

    println!("block encrypted (rounds: {}) {:?}", rounds, start.elapsed());

    fhe_model::fhe_decrypt_byte_array(&context.client_key, &encrypted)
}

#[derive(Clone)]
struct FheContext {
    client_key: Arc<shortint::client_key::ClientKey>,
    server_key: Arc<shortint::server_key::ServerKey>,
    wopbs_key: Arc<shortint::wopbs::WopbsKey>,
}

impl Debug for FheContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FheContext").finish()
    }
}

fn collect_array<const N: usize, T: Send + Sync + Debug>(
    iter: impl IntoParallelIterator<Item = T>,
) -> [T; N] {
    iter.into_par_iter()
        .collect::<Vec<_>>()
        .try_into()
        .expect("array length")
}

fn shl_array<const N: usize, T: Default>(array: &mut [T; N], shl: usize) {
    for i in 0..N {
        if i + shl < N {
            array[i] = mem::take(&mut array[i + shl]);
        } else {
            array[i] = T::default();
        }
    }
}

#[cfg(test)]
mod test {
    use crate::impls::tfhe_pbssub_wop_shortint::model::BoolByte;
    use crate::impls::tfhe_pbssub_wop_shortint::shl_array;

    #[test]
    fn test_bool_byte() {
        let byte = 0x12;
        assert_eq!(u8::from(BoolByte::from(byte)), byte);
    }

    #[test]
    fn test_shl_array() {
        let mut array = [3, 4, 5, 6];
        shl_array(&mut array, 2);
        assert_eq!(array, [5, 6, 0, 0]);

        let mut array = [3, 4, 5, 6];
        shl_array(&mut array, 0);
        assert_eq!(array, [3, 4, 5, 6]);

        let mut array = [3, 4, 5, 6];
        shl_array(&mut array, 5);
        assert_eq!(array, [0, 0, 0, 0]);
    }

    use crate::impls::{tfhe_pbssub_shortint, tfhe_pbssub_wop_shortint};
    use crate::{impls, ROUNDS};

    #[test]
    fn test_tfhe_pbssub_wop_shortint_two_rounds() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build_global()
            .unwrap();
        println!("current_num_threads: {}", rayon::current_num_threads());

        impls::test::test_vs_plain(tfhe_pbssub_wop_shortint::encrypt_single_block, 2);
    }

    #[test]
    fn test_tfhe_pbssub_wop_shortint_all_rounds() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build_global()
            .unwrap();

        impls::test::test_vs_plain(tfhe_pbssub_wop_shortint::encrypt_single_block, ROUNDS);
    }
}
