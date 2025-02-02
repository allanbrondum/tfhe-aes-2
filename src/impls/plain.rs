use crate::{Block, Key};
use std::ops::{BitXor, BitXorAssign, Index, IndexMut};

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

/// State of 4 rows each of 4 bytes
#[derive(Debug, Default)]
struct State([Word; 4]);

impl State {
    pub fn from_array(block: &[u8; 16]) -> Self {
        let mut this = Self::default();
        for i in 0..16 {
            this[i % 4][i / 4] = block[i];
        }
        this
    }

    pub fn to_array(&self) -> [u8; 16] {
        let mut array: [u8; 16] = Default::default();
        for i in 0..16 {
            array[i] = self[i % 4][i / 4];
        }
        array
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut u8> {
        self.0.iter_mut().flat_map(|w| w.0.iter_mut())
    }

    pub fn rows_mut(&mut self) -> impl Iterator<Item = &mut Word> {
        self.0.iter_mut()
    }

    pub fn column(&self, j: usize) -> Word {
        let mut col: Word = Default::default();
        for i in 0..4 {
            col.0[i] = self.0[i][j];
        }
        col
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

#[derive(Debug, Default, Copy, Clone)]
pub struct Word([u8; 4]);

impl Word {
    pub const fn zero() -> Self {
        Self([0; 4])
    }

    pub fn bytes_mut(&mut self) -> impl Iterator<Item = &mut u8> {
        self.0.iter_mut()
    }

    pub fn rotate_left(mut self, mid: usize) -> Self {
        self.0.rotate_left(mid);
        self
    }
}

impl BitXorAssign for Word {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (byte, rhs_byte) in self.0.iter_mut().zip(rhs.0.iter()) {
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
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Word {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

fn substitute(byte: u8) -> u8 {
    SBOX[byte as usize]
}

fn sub_bytes(state: &mut State) {
    for byte in state.bytes_mut() {
        *byte = substitute(*byte);
    }
}

fn shift_rows(state: &mut State) {
    for (i, row) in state.rows_mut().enumerate() {
        *row = row.rotate_left(i);
    }
}

/// Multiplication in F_2[X]/(X^8 + X^4 + X^3 + X + 1)
fn gf_256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        if b & 1 == 1 {
            res ^= a
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0x80 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    res
}

fn mix_columns(state: &mut State) {
    for j in 0..4 {
        let col = state.column(j);

        state[0][j] = gf_256_mul(col[0], 2)
            ^ gf_256_mul(col[3], 1)
            ^ gf_256_mul(col[2], 1)
            ^ gf_256_mul(col[1], 3);
        state[1][j] = gf_256_mul(col[1], 2)
            ^ gf_256_mul(col[0], 1)
            ^ gf_256_mul(col[3], 1)
            ^ gf_256_mul(col[2], 3);
        state[2][j] = gf_256_mul(col[2], 2)
            ^ gf_256_mul(col[1], 1)
            ^ gf_256_mul(col[0], 1)
            ^ gf_256_mul(col[3], 3);
        state[3][j] = gf_256_mul(col[3], 2)
            ^ gf_256_mul(col[2], 1)
            ^ gf_256_mul(col[1], 1)
            ^ gf_256_mul(col[0], 3);
    }
}

pub fn encrypt_block(expanded_key: &[Word; 44], block: Block, rounds: usize) -> Block {
    let mut state = State::from_array(&block);

    state ^= expanded_key[0..4].try_into().expect("array length 4");

    for i in 1..rounds {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        state ^= expanded_key[i * 4..(i + 1) * 4]
            .try_into()
            .expect("array length 4");
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    state ^= expanded_key[40..44].try_into().expect("array length 4");

    state.to_array()
}

pub fn key_schedule(key_slice: &Key) -> [Word; 44] {
    let mut key: [Word; 4] = Default::default();
    let mut expanded_key: [Word; 44] = [Word::zero(); 44];

    for i in 0..4 {
        key[i] = Word(
            key_slice[i * 4..(i + 1) * 4]
                .try_into()
                .expect("array length 4"),
        );
    }

    for i in 0..4 {
        expanded_key[i] = key[i];
    }

    for i in 4..44 {
        if i % 4 == 0 {
            let mut rcon = Word::default();
            rcon[0] = RC[i / 4];
            expanded_key[i] =
                expanded_key[i - 4] ^ sub_word(expanded_key[i - 1].rotate_left(1)) ^ rcon;
        } else {
            expanded_key[i] = expanded_key[i - 4] ^ expanded_key[i - 1];
        }
    }

    expanded_key
}

fn sub_word(mut word: Word) -> Word {
    for byte in word.bytes_mut() {
        *byte = substitute(*byte);
    }
    word
}

pub fn encrypt_single_block(key: Key, block: Block, rounds: usize) -> Block {
    let key_schedule = key_schedule(&key);
    let encrypted = encrypt_block(&key_schedule, block, rounds);
    encrypted
}
