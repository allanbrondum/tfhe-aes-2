use crate::impls::tfhe_boolean::model::{BoolByte, State, Word};
use crate::impls::tfhe_boolean::FheContext;
use rayon::iter::ParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge};
use std::fmt::{Debug, Formatter};
use std::mem;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use tfhe::boolean;
use tfhe::boolean::server_key::{BinaryBooleanGates, BinaryBooleanGatesAssign};

pub type BlockFhe = [BoolByteFhe; 16];

#[derive(Clone)]
pub struct BoolFhe {
    fhe: boolean::ciphertext::Ciphertext,
    context: Option<FheContext>,
}

impl BoolFhe {
    pub fn new(fhe: boolean::ciphertext::Ciphertext, context: FheContext) -> Self {
        Self {
            fhe,
            context: Some(context),
        }
    }

    pub const fn trivial(b: bool) -> Self {
        Self {
            fhe: boolean::ciphertext::Ciphertext::Trivial(b),
            context: None,
        }
    }

    // pub fn mux(&self, then: &Self, r#else: &Self) -> Self {
    //     if let Some(context) = self.context.as_ref() {
    //         BoolFhe::new(
    //             context.server_key.mux(&self.fhe, &then.fhe, &r#else.fhe),
    //             context.clone(),
    //         )
    //     } else if let boolean::ciphertext::Ciphertext::Trivial(this) = &self.fhe {
    //         if *this {
    //             then.clone()
    //         } else {
    //             r#else.clone()
    //         }
    //     } else {
    //         panic!("no fhe context and non-trivial operands");
    //     }
    // }
}

impl Debug for BoolFhe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoolFhe")
            .field("fhe", &self.fhe)
            .field("context", &self.context.as_ref().map(|_| ()))
            .finish()
    }
}

impl Default for BoolFhe {
    fn default() -> Self {
        Self::trivial(false)
    }
}

impl BitXorAssign<&BoolFhe> for BoolFhe {
    fn bitxor_assign(&mut self, rhs: &Self) {
        if let Some(context) = self.context.as_ref().or(rhs.context.as_ref()) {
            context.server_key.xor_assign(&mut self.fhe, &rhs.fhe);
            self.context = Some(context.clone());
        } else if let (
            boolean::ciphertext::Ciphertext::Trivial(this),
            boolean::ciphertext::Ciphertext::Trivial(rhs),
        ) = (&mut self.fhe, &rhs.fhe)
        {
            this.bitxor_assign(rhs);
        } else {
            panic!(
                "no fhe context and non-trivial operands {:?} {:?}",
                self, rhs
            );
        }
    }
}

impl BitXor for BoolFhe {
    type Output = BoolFhe;

    fn bitxor(mut self, rhs: BoolFhe) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
    }
}

// impl BitAnd<BoolFhe> for &BoolFhe {
//     type Output = BoolFhe;
//
//     fn bitand(self, rhs: BoolFhe) -> Self::Output {
//         if let Some(context) = self.context.as_ref().or(rhs.context.as_ref()) {
//             BoolFhe::new(context.server_key.and(&self.fhe, &rhs.fhe), context.clone())
//         } else if let (
//             boolean::ciphertext::Ciphertext::Trivial(this),
//             boolean::ciphertext::Ciphertext::Trivial(rhs),
//         ) = (&self.fhe, &rhs.fhe)
//         {
//             BoolFhe::trivial(this.bitand(rhs))
//         } else {
//             panic!("no fhe context and non-trivial operands");
//         }
//     }
// }

#[derive(Debug, Clone, Default)]
pub struct BoolByteFhe([BoolFhe; 8]);

impl BoolByteFhe {
    pub const fn zero() -> Self {
        Self([const { BoolFhe::trivial(false) }; 8])
    }

    pub fn shl_assign_1(&mut self) -> BoolFhe {
        let ret = mem::take(&mut self.0[0]);
        self.shl_assign(1);
        ret
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

impl<'a> ColumnViewFhe<'a> {
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

impl<'a> Index<usize> for ColumnViewFhe<'a> {
    type Output = BoolByteFhe;

    fn index(&self, row: usize) -> &Self::Output {
        &self.1[row][self.0]
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
    pub const fn zero() -> Self {
        Self([const { BoolByteFhe::zero() }; 4])
    }

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
    BoolFhe::new(client_key.encrypt(b), context.clone())
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

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    fn keys() -> (Arc<boolean::client_key::ClientKey>, FheContext) {
        let (client_key, server_key) = boolean::gen_keys();

        let context = FheContext {
            client_key: client_key.clone().into(),
            server_key: server_key.into(),
        };

        (context.client_key.clone(), context)
    }

    #[test]
    fn test_bool_fhe() {
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
    fn test_bool_perf() {
        let start = Instant::now();
        let (client_key, context) = keys();
        println!("keys generated: {:?}", start.elapsed());

        let start = Instant::now();
        let mut b1 = client_key.encrypt(false);
        let b2 = client_key.encrypt(true);
        println!("data encrypted: {:?}", start.elapsed());

        let start = Instant::now();
        context.server_key.xor_assign(&mut b1, &b2);
        println!("xor bootstrap elapsed: {:?}", start.elapsed());
    }
}
