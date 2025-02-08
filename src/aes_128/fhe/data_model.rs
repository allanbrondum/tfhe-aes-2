use crate::tfhe::ContextT;
use rayon::iter::{
    IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use rayon::prelude::IndexedParallelIterator;
use std::fmt::Debug;
use std::ops::{BitXor, BitXorAssign, Index, IndexMut};
use std::{array, mem};
use tfhe::core_crypto::entities::Cleartext;

pub trait BitT:
    for<'a> BitXorAssign<&'a Self> + Send + Sync + Clone + Debug + Sized + 'static
{
}

pub trait ByteT: Sized {
    /// Bootstrap to reset noise
    fn bootstrap(&self) -> Self;

    /// Perform AES SubBytes on this byte while also resetting noise
    fn aes_substitute(&self) -> Self;
}

/// Byte represented as individual bits
#[derive(Debug, Clone)]
pub struct Byte<Bit>(pub [Bit; 8]);

impl<Bit: Send + Sync> Byte<Bit> {
    pub fn new(bits: [Bit; 8]) -> Self {
        Self(bits)
    }

    pub fn bits(&self) -> impl IndexedParallelIterator<Item = &Bit> + '_ {
        self.0.par_iter()
    }

    pub fn bits_mut(&mut self) -> impl IndexedParallelIterator<Item = &mut Bit> + '_ {
        self.0.par_iter_mut()
    }
}

impl<Bit> Byte<Bit> {
    pub fn trivial(ctx: &impl ContextT<Bit = Bit>, val: u8) -> Self {
        Self(array::from_fn(|i| {
            ctx.trivial(if 0 == (val & (0x80 >> i)) {
                Cleartext(0)
            } else {
                Cleartext(1)
            })
        }))
    }

    pub fn shl_assign_1(&mut self, ctx: &impl ContextT<Bit = Bit>) -> Bit {
        let ret = mem::replace(&mut self.0[0], ctx.trivial(Cleartext(0)));
        self.0.rotate_left(1);
        ret
    }
}

impl<Bit> Index<usize> for Byte<Bit> {
    type Output = Bit;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<Bit> IndexMut<usize> for Byte<Bit> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

// impl<Bit: BitT> ShlAssign<usize> for Byte<Bit> {
//     fn shl_assign(&mut self, rhs: usize) {
//         util::shl_array(&mut self.0, rhs);
//     }
// }

impl<Bit: BitT> BitXorAssign<&Byte<Bit>> for Byte<Bit> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.bits_mut().zip(rhs.bits()).for_each(|(b, rhs_b)| {
            *b ^= rhs_b;
        });
    }
}

impl<Bit: BitT> BitXor for Byte<Bit> {
    type Output = Byte<Bit>;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Word<Bit>(pub [Byte<Bit>; 4]);

impl<Bit: Send + Sync> Word<Bit> {
    pub fn new(bytes: [Byte<Bit>; 4]) -> Self {
        Self(bytes)
    }

    pub fn zero(ctx: &impl ContextT<Bit = Bit>) -> Self {
        Self(array::from_fn(|_| Byte::trivial(ctx, 0)))
    }

    pub fn bytes(&self) -> impl IndexedParallelIterator<Item = &Byte<Bit>> + '_ {
        self.0.par_iter()
    }

    pub fn into_bytes(self) -> impl IndexedParallelIterator<Item = Byte<Bit>> {
        self.0.into_par_iter()
    }

    pub fn bytes_mut(&mut self) -> impl IndexedParallelIterator<Item = &mut Byte<Bit>> {
        self.0.par_iter_mut()
    }

    pub fn rotate_left(mut self, mid: usize) -> Self {
        self.rotate_left_assign(mid);
        self
    }

    pub fn rotate_left_assign(&mut self, mid: usize) {
        self.0.rotate_left(mid);
    }
}

impl<Bit> Index<usize> for Word<Bit> {
    type Output = Byte<Bit>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<Bit> IndexMut<usize> for Word<Bit> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<Bit: BitT> BitXorAssign<&Self> for Word<Bit> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
    }
}

impl<Bit: BitT> BitXor<&Word<Bit>> for Word<Bit> {
    type Output = Word<Bit>;

    fn bitxor(mut self, rhs: &Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

pub type Block<Bit> = [Byte<Bit>; 16];

/// State of 4 rows each of 4 bytes
#[derive(Debug)]
pub struct State<Bit>([Word<Bit>; 4]);

impl<Bit: BitT> State<Bit> {
    pub fn from_array(block: [Byte<Bit>; 16]) -> Self {
        let mut block_opts = block.map(Some);
        Self(array::from_fn(|i| {
            Word(array::from_fn(|j| {
                block_opts[4 * j + i].take().expect("item")
            }))
        }))
    }

    pub fn into_array(self) -> [Byte<Bit>; 16] {
        let mut self_opts = self.0.map(|word| word.0.map(Some));
        array::from_fn(|i| self_opts[i % 4][i / 4].take().expect("item"))
    }

    pub fn bytes_mut(&mut self) -> impl ParallelIterator<Item = &mut Byte<Bit>> {
        self.0.par_iter_mut().flat_map(|w| w.0.par_iter_mut())
    }

    pub fn rows_mut(&mut self) -> impl IndexedParallelIterator<Item = &mut Word<Bit>> {
        self.0.par_iter_mut()
    }

    pub fn columns(&self) -> impl IndexedParallelIterator<Item = ColumnViewFhe<'_, Bit>> {
        (0..4).into_par_iter().map(|j| ColumnViewFhe(j, &self.0))
    }

    pub fn column(&self, j: usize) -> ColumnViewFhe<'_, Bit> {
        ColumnViewFhe(j, &self.0)
    }

    pub fn column_mut(&mut self, j: usize) -> ColumnViewMutFhe<'_, Bit> {
        ColumnViewMutFhe(j, &mut self.0)
    }
}

impl<Bit> Index<usize> for State<Bit> {
    type Output = Word<Bit>;

    fn index(&self, row: usize) -> &Self::Output {
        &self.0[row]
    }
}

impl<Bit> IndexMut<usize> for State<Bit> {
    fn index_mut(&mut self, row: usize) -> &mut Self::Output {
        &mut self.0[row]
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ColumnViewFhe<'a, Bit>(usize, &'a [Word<Bit>; 4]);

impl<Bit: BitT> ColumnViewFhe<'_, Bit> {
    pub fn bytes(&self) -> impl IndexedParallelIterator<Item = &Byte<Bit>> + '_ {
        (0..4).into_par_iter().map(|i| &self.1[i][self.0])
    }

    pub fn clone_to_word(&self) -> Word<Bit> {
        Word(array::from_fn(|i| self.1[i][self.0].clone()))
    }
}

impl<Bit> Index<usize> for ColumnViewFhe<'_, Bit> {
    type Output = Byte<Bit>;

    fn index(&self, row: usize) -> &Self::Output {
        &self.1[row][self.0]
    }
}

#[derive(Debug)]
pub struct ColumnViewMutFhe<'a, Bit>(usize, &'a mut [Word<Bit>; 4]);

impl<Bit: BitT> ColumnViewMutFhe<'_, Bit> {
    pub fn bytes(&self) -> impl IndexedParallelIterator<Item = &Byte<Bit>> + '_ {
        (0..4).into_par_iter().map(|i| &self.1[i][self.0])
    }

    pub fn bytes_mut(&mut self) -> impl IndexedParallelIterator<Item = &'_ mut Byte<Bit>> + '_ {
        self.1.into_par_iter().map(|row| &mut row[self.0])
    }

    pub fn bitxor_assign(&mut self, rhs: &Word<Bit>) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
    }

    pub fn assign(&mut self, rhs: Word<Bit>) {
        rhs.0.into_iter().enumerate().for_each(|(i, byte)| {
            self.1[i][self.0] = byte;
        });
    }
}
