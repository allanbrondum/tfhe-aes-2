use crate::util;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use std::fmt::Debug;
use std::mem;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut, ShlAssign};
use tfhe::core_crypto::entities::Cleartext;
use tfhe::core_crypto::prelude::ContiguousEntityContainer;

pub trait BitT:
    for<'a> BitXorAssign<&'a Self> + Send + Sync + Clone + Debug + Default + Sized + 'static
{
    fn trivial(val: Cleartext<u8>) -> Self;
}

pub trait ByteT: Sized {
    /// Bootstrap to reset noise
    fn bootstrap(&self) -> Self;

    /// Perform AES SubBytes on this byte while also resetting noise
    fn aes_substitute(&self) -> Self;
}

#[derive(Debug, Clone, Default)]
pub struct Byte<Bit>([Bit; 8]);

impl<Bit> Byte<Bit> {
    pub fn new(bits: [Bit; 8]) -> Self {
        Self(bits)
    }

    pub fn bits(&self) -> impl Iterator<Item = &Bit> + '_ {
        self.0.iter()
    }

    pub fn bits_mut(&mut self) -> impl Iterator<Item = &mut Bit> + '_ {
        self.0.iter_mut()
    }
}

impl<Bit: BitT> Byte<Bit> {
    pub fn trivial(val: u8) -> Self {
        let mut byte = Byte::default();
        for i in 0..8 {
            byte[i] = Bit::trivial(if 0 == (val & (0x80 >> i)) { Cleartext(0) } else { Cleartext(1) });
        }
        byte
    }

    pub fn shl_assign_1(&mut self) -> Bit {
        let ret = mem::take(&mut self.0[0]);
        self.shl_assign(1);
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

impl<Bit: BitT> ShlAssign<usize> for Byte<Bit> {
    fn shl_assign(&mut self, rhs: usize) {
        util::shl_array(&mut self.0, rhs);
    }
}

impl<Bit: BitT> BitXorAssign<&Byte<Bit>> for Byte<Bit> {
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

impl<Bit: BitT> BitXor for Byte<Bit> {
    type Output = Byte<Bit>;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(&rhs);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Word<Bit>([Byte<Bit>; 4]);

impl<Bit> Word<Bit> {
    pub fn new(bytes: [Byte<Bit>; 4]) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> impl Iterator<Item = &Byte<Bit>> + '_ {
        self.0.iter()
    }

    pub fn into_bytes(self) -> impl Iterator<Item = Byte<Bit>> {
        self.0.into_iter()
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut Byte<Bit>> {
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
            .par_bridge()
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
#[derive(Debug, Default)]
pub struct State<Bit>([Word<Bit>; 4]);

impl<Bit: BitT> State<Bit> {
    pub fn from_array(block: [Byte<Bit>; 16]) -> Self {
        let mut this = Self::default();
        for (i, byte) in block.into_iter().enumerate() {
            this[i % 4][i / 4] = byte;
        }
        this
    }

    pub fn into_array(self) -> [Byte<Bit>; 16] {
        let mut array: [Byte<Bit>; 16] = Default::default();
        for (i, row) in self.0.into_iter().enumerate() {
            for (j, byte) in row.0.into_iter().enumerate() {
                array[i + j * 4] = byte;
            }
        }
        array
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut Byte<Bit>> {
        self.0.iter_mut().flat_map(|w| w.0.iter_mut())
    }

    pub fn rows_mut(&mut self) -> impl Iterator<Item = &mut Word<Bit>> {
        self.0.iter_mut()
    }

    pub fn columns(&self) -> impl Iterator<Item = ColumnViewFhe<'_, Bit>> {
        (0..4).map(|j| ColumnViewFhe(j, &self.0))
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
    pub fn bytes(&self) -> impl Iterator<Item = &Byte<Bit>> + '_ {
        (0..4).map(|i| &self.1[i][self.0])
    }

    pub fn clone_to_word(&self) -> Word<Bit> {
        Word(util::collect_array(
            (0..4).map(|i| self.1[i][self.0].clone()),
        ))
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
    pub fn bytes(&self) -> impl Iterator<Item = &Byte<Bit>> + '_ {
        (0..4).map(|i| &self.1[i][self.0])
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &'_ mut Byte<Bit>> + '_ {
        self.1.iter_mut().map(|row| &mut row[self.0])
    }

    pub fn bitxor_assign(&mut self, rhs: &Word<Bit>) {
        self.bytes_mut()
            .zip(rhs.bytes())
            .par_bridge()
            .for_each(|(byte, rhs_byte)| {
                *byte ^= rhs_byte;
            });
    }

    pub fn assign(&mut self, rhs: Word<Bit>) {
        for (i, byte) in rhs.into_bytes().enumerate() {
            self.1[i][self.0] = byte;
        }
    }
}
