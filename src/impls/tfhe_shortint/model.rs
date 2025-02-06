use std::ops::{BitXor, BitXorAssign, Index, IndexMut, ShlAssign};

#[derive(Debug, Default, Copy, Clone)]
pub struct BoolByte(pub [bool; 8]);

impl BoolByte {
    const fn zero() -> Self {
        Self([false; 8])
    }

    pub fn shl_assign_1(&mut self) -> bool {
        let ret = self.0[0];
        self.shl_assign(1);
        ret
    }
}

impl Index<usize> for BoolByte {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for BoolByte {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl ShlAssign<usize> for BoolByte {
    fn shl_assign(&mut self, rhs: usize) {
        super::shl_array(&mut self.0, rhs);
    }
}

impl BitXorAssign for BoolByte {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (b, rhs_b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *b ^= rhs_b;
        }
    }
}

impl BitXor for BoolByte {
    type Output = BoolByte;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

impl From<u8> for BoolByte {
    fn from(value: u8) -> Self {
        let mut byte = BoolByte::default();
        for i in 0..8 {
            byte[i] = 0 != (value & (0x80 >> i));
        }
        byte
    }
}

impl From<BoolByte> for u8 {
    fn from(value: BoolByte) -> Self {
        let mut byte = u8::default();
        for i in 0..8 {
            byte |= if value[i] { 0x80 >> i } else { 0 };
        }
        byte
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Word(pub [BoolByte; 4]);

impl Word {
    pub const fn zero() -> Self {
        Self([BoolByte::zero(); 4])
    }

    pub fn bytes(&self) -> impl Iterator<Item = BoolByte> + '_ {
        self.0.iter().copied()
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut BoolByte> {
        self.0.iter_mut()
    }

    pub fn rotate_left(mut self, mid: usize) -> Self {
        self.0.rotate_left(mid);
        self
    }
}

impl BitXorAssign for Word {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (byte, rhs_byte) in self.bytes_mut().zip(rhs.bytes()) {
            *byte ^= rhs_byte;
        }
    }
}

impl BitXor for Word {
    type Output = Word;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

impl Index<usize> for Word {
    type Output = BoolByte;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Word {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/// State of 4 rows each of 4 bytes
#[derive(Debug, Default)]
pub struct State([Word; 4]);

impl State {
    pub fn from_array(block: &[u8; 16]) -> Self {
        let mut this = Self::default();
        for i in 0..16 {
            this[i % 4][i / 4] = block[i].into();
        }
        this
    }

    pub fn to_array(&self) -> [u8; 16] {
        let mut array: [u8; 16] = Default::default();
        for i in 0..16 {
            array[i] = self[i % 4][i / 4].into();
        }
        array
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut BoolByte> {
        self.0.iter_mut().flat_map(|w| w.0.iter_mut())
    }

    pub fn rows_mut(&mut self) -> impl Iterator<Item = &mut Word> {
        self.0.iter_mut()
    }

    pub fn column(&self, j: usize) -> ColumnView<'_> {
        ColumnView(j, &self.0)
    }

    pub fn column_mut(&mut self, j: usize) -> ColumnViewMut<'_> {
        ColumnViewMut(j, &mut self.0)
    }
}

impl BitXorAssign<&[Word; 4]> for State {
    fn bitxor_assign(&mut self, rhs: &[Word; 4]) {
        for (word, rhs_word) in self.0.iter_mut().zip(rhs.iter()) {
            *word ^= *rhs_word;
        }
    }
}

impl Index<usize> for State {
    type Output = Word;

    fn index(&self, row: usize) -> &Self::Output {
        &self.0[row]
    }
}

impl IndexMut<usize> for State {
    fn index_mut(&mut self, row: usize) -> &mut Self::Output {
        &mut self.0[row]
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ColumnView<'a>(usize, &'a [Word; 4]);

impl<'a> ColumnView<'a> {
    pub fn to_word(&self) -> Word {
        let mut col: Word = Default::default();
        for i in 0..4 {
            col.0[i] = self.1[i][self.0];
        }
        col
    }
}

#[derive(Debug)]
pub struct ColumnViewMut<'a>(usize, &'a mut [Word; 4]);

impl ColumnViewMut<'_> {
    pub fn bytes(&self) -> impl Iterator<Item = BoolByte> + '_ {
        (0..4).map(|i| self.1[i][self.0])
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &'_ mut BoolByte> + '_ {
        self.1.iter_mut().map(|row| &mut row[self.0])
    }

    pub fn bitxor_assign(&mut self, rhs: Word) {
        for (byte, rhs_byte) in self.bytes_mut().zip(rhs.bytes()) {
            *byte ^= rhs_byte;
        }
    }
}
