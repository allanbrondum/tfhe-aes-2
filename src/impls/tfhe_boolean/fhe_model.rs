use crate::impls::tfhe_boolean::model::{BoolByte, State, Word};
use crate::impls::tfhe_boolean::FheContext;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::ops::{BitXorAssign, Index, IndexMut};
use tfhe::boolean;
use tfhe::boolean::server_key::{BinaryBooleanGates, BinaryBooleanGatesAssign};

pub type BlockFhe = [BoolByteFhe; 16];

#[derive(Debug, Clone)]
pub struct BoolFhe {
    fhe: boolean::ciphertext::Ciphertext,
    context: Option<FheContext>,
}

impl BoolFhe {
    const fn const_false() -> Self {
        Self {
            fhe: boolean::ciphertext::Ciphertext::Trivial(false),
            context: None,
        }
    }
}

impl Default for BoolFhe {
    fn default() -> Self {
        Self::const_false()
    }
}

impl BitXorAssign<&BoolFhe> for BoolFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.context.as_ref().expect("conext").server_key.xor_assign(&mut self.fhe, &rhs.fhe);
    }
}

#[derive(Debug, Clone, Default)]
pub struct BoolByteFhe([BoolFhe; 8]);

impl BoolByteFhe {
    const fn zero() -> Self {
        Self([const { BoolFhe::const_false() }; 8])
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


impl BitXorAssign<&BoolByteFhe> for BoolByteFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        for (b, rhs_b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *b ^= rhs_b;
        }
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

    pub fn column(&self, j: usize) -> ColumnViewFhe<'_> {
        ColumnViewFhe(j, &self.0)
    }

    pub fn column_mut(&mut self, j: usize) -> ColumnViewMutFhe<'_> {
        ColumnViewMutFhe(j, &mut self.0)
    }
}

// impl BitXorAssign<&[Word; 4]> for StateFhe {
//     fn bitxor_assign(&mut self, rhs: &[Word; 4]) {
//         for (word, rhs_word) in self.0.iter_mut().zip(rhs.iter()) {
//             *word ^= *rhs_word;
//         }
//     }
// }

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

impl<'a> ColumnViewFhe<'a> {
    fn clone_to_word(&self) -> WordFhe {
        let mut col: WordFhe = Default::default();
        for i in 0..4 {
            col.0[i] = self.1[i][self.0].clone();
        }
        col
    }
}

#[derive(Debug)]
pub struct ColumnViewMutFhe<'a>(usize, &'a mut [WordFhe; 4]);

impl<'a> ColumnViewMutFhe<'a> {
    pub fn bytes(&self) -> impl Iterator<Item = &BoolByteFhe> + '_ {
        (0..4).map(|i| &self.1[i][self.0])
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &'_ mut BoolByteFhe> + '_ {
        self.1.iter_mut().map(|row| &mut row[self.0])
    }

    pub fn bitxor_assign(&mut self, rhs: &WordFhe) {
        for (byte, rhs_byte) in self.bytes_mut().zip(rhs.bytes()) {
            *byte ^= rhs_byte;
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WordFhe([BoolByteFhe; 4]);

impl WordFhe {
    pub const fn zero() -> Self {
        Self([const { BoolByteFhe::zero() }; 4])
    }

    pub fn bytes(&self) -> impl Iterator<Item = &BoolByteFhe> + '_ {
        self.0.iter()
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
        for (byte, rhs_byte) in self.bytes_mut().zip(rhs.bytes()) {
            *byte ^= rhs_byte;
        }
    }
}


pub fn fhe_encrypt_word_array<const N: usize>(
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
    context: &FheContext,
    b: bool,
) -> BoolFhe {
    BoolFhe {
        fhe: client_key.encrypt(b),
        context: Some(context.clone()),
    }
}

pub fn fhe_decrypt_word_array<const N: usize>(
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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
    client_key: &boolean::client_key::ClientKey,
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

pub fn fhe_decrypt_bool(client_key: &boolean::client_key::ClientKey, b: &BoolFhe) -> bool {
    client_key.decrypt(&b.fhe)
}

pub fn fhe_decrypt_state(context: &FheContext, state_fhe: StateFhe) -> State {
    let array = fhe_decrypt_byte_array(&context.client_key, &state_fhe.into_array());
    State::from_array(&array)
}

pub fn fhe_encrypt_state(context: &FheContext, state: State) -> StateFhe {
    let array = fhe_encrypt_byte_array(&context.client_key, context, &state.to_array());
    StateFhe::from_array(array)
}
