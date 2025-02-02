use crate::{Block, Key};
use std::convert::AsMut;

static SBOX: [[u8; 16]; 16] = [
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
    ],
    [
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
        0xc0,
    ],
    [
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31,
        0x15,
    ],
    [
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2,
        0x75,
    ],
    [
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f,
        0x84,
    ],
    [
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
        0xcf,
    ],
    [
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f,
        0xa8,
    ],
    [
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3,
        0xd2,
    ],
    [
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73,
    ],
    [
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b,
        0xdb,
    ],
    [
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
        0x79,
    ],
    [
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae,
        0x08,
    ],
    [
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b,
        0x8a,
    ],
    [
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d,
        0x9e,
    ],
    [
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28,
        0xdf,
    ],
    [
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ],
];

static RC: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

fn substitute(byte: u8) -> u8 {
    let upper_nibble: usize;
    let lower_nibble: usize;
    upper_nibble = ((byte >> 4) & 0xF).into();
    lower_nibble = (byte & 0xF).into();

    SBOX[upper_nibble][lower_nibble]
}

fn rot_word(word: &[u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];

    for i in 0..4 {
        result[i] = word[(i + 1) % 4];
    }

    result
}

fn sub_word(word: &[u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];

    for i in 0..4 {
        result[i] = substitute(word[i]);
    }

    result
}

fn xor_words(word1: &[u8; 4], word2: &[u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];

    for i in 0..4 {
        result[i] = word1[i] ^ word2[i];
    }

    result
}

fn add_round_key(state: &mut [[u8; 4]; 4], key: &[[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = state[i][j] ^ key[j][i];
        }
    }
}

fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = substitute(state[i][j]);
        }
    }
}

fn shift_rows(state: &mut [[u8; 4]; 4]) {
    for i in 1..4 {
        let mut tmp = vec![0u8; i];
        for j in 0..i {
            tmp[j] = state[i][j];
        }
        for j in 0..4 - i {
            state[i][j] = state[i][j + i];
        }
        for j in 0..i {
            state[i][3 - j] = tmp[i - j - 1];
        }
    }
}

fn galois_multiplication(ap: u8, bp: u8) -> u8 {
    let mut p = 0u8;
    let mut high_bit = 0u8;
    let mut a = ap;
    let mut b = bp;
    for i in 0..8 {
        if b & 1 == 1 {
            p ^= a
        }
        high_bit = a & 0x80;
        a = (a << 1) & 0xFF;
        if high_bit == 0x80 {
            a ^= 0x1b;
        }
        b = (b >> 1) & 0xFF;
    }
    p & 0xFF
}

fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let mut temp = [0u8; 4];
        for j in 0..4 {
            temp[j] = state[j][i];
        }

        state[0][i] = galois_multiplication(temp[0], 2)
            ^ galois_multiplication(temp[3], 1)
            ^ galois_multiplication(temp[2], 1)
            ^ galois_multiplication(temp[1], 3);
        state[1][i] = galois_multiplication(temp[1], 2)
            ^ galois_multiplication(temp[0], 1)
            ^ galois_multiplication(temp[3], 1)
            ^ galois_multiplication(temp[2], 3);
        state[2][i] = galois_multiplication(temp[2], 2)
            ^ galois_multiplication(temp[1], 1)
            ^ galois_multiplication(temp[0], 1)
            ^ galois_multiplication(temp[3], 3);
        state[3][i] = galois_multiplication(temp[3], 2)
            ^ galois_multiplication(temp[2], 1)
            ^ galois_multiplication(temp[1], 1)
            ^ galois_multiplication(temp[0], 3);
    }
}

pub fn key_schedule(key_bytes: &Key) -> [[u8; 4]; 44] {
    let mut original_key = [[0u8; 4]; 4];
    let mut expanded_key = [[0u8; 4]; 44];
    let N = 4;

    for i in 0..16 {
        original_key[i / 4][i % 4] = key_bytes[i];
    }

    for i in 0..44 {
        // 11 rounds, i in 0..4*rounds-1

        if i < N {
            expanded_key[i] = original_key[i];
        } else if i >= N && i % N == 0 {
            let mut rcon = [0u8; 4];
            rcon[0] = RC[i / N];
            expanded_key[i] = xor_words(
                &xor_words(
                    &expanded_key[i - N],
                    &sub_word(&rot_word(&expanded_key[i - 1])),
                ),
                &rcon,
            );
        } else {
            expanded_key[i] = xor_words(&expanded_key[i - N], &expanded_key[i - 1]);
        }
    }

    expanded_key
}

pub fn encrypt_block(expanded_key: [[u8; 4]; 44], bytes: &Block, rounds: usize) -> Block {
    let mut result = [0u8; 16];

    let mut state = [[0u8; 4]; 4];
    for i in 0..16 {
        state[i % 4][i / 4] = bytes[i];
    }

    add_round_key(&mut state, &clone_into_array(&expanded_key[0..4]));

    for i in 1..rounds {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(
            &mut state,
            &clone_into_array(&expanded_key[i * 4..(i + 1) * 4]),
        );
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &clone_into_array(&expanded_key[40..44]));

    for i in 0..4 {
        for j in 0..4 {
            result[4 * j + i] = state[i][j]
        }
    }

    result
}

pub fn encrypt_single_block(key: Key, block: Block, rounds: usize) -> Block {
    let key_schedule = key_schedule(&key);
    let encrypted = encrypt_block(key_schedule, &block, rounds);
    encrypted
}
