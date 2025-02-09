use rayon::iter::{IntoParallelIterator, ParallelIterator};

use std::{array, mem};

pub fn par_collect_array<const N: usize, T: Send + Sync>(
    iter: impl IntoParallelIterator<Item = T>,
) -> [T; N] {
    iter.into_par_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ())
        .expect("array length")
}

pub fn collect_array<const N: usize, T: Send + Sync>(iter: impl IntoIterator<Item = T>) -> [T; N] {
    iter.into_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ())
        .expect("array length")
}

pub fn shl_array<const N: usize, T: Default>(array: &mut [T; N], shl: usize) {
    for i in 0..N {
        if i + shl < N {
            array[i] = mem::take(&mut array[i + shl]);
        } else {
            array[i] = T::default();
        }
    }
}

pub fn u8_to_bits(byte: u8) -> [u8; 8] {
    array::from_fn(|i| if 0 == (byte & (0x80 >> i)) { 0 } else { 1 })
}

pub fn bits_to_u8(bits: [u8; 8]) -> u8 {
    bits.into_iter()
        .enumerate()
        .map(|(i, bit)| bit << (7 - i))
        .sum()
}

pub fn u16_to_bits(word: u16) -> [u8; 16] {
    array::from_fn(|i| if 0 == (word & (0x8000 >> i)) { 0 } else { 1 })
}

pub fn bits_to_u16(bits: [u8; 16]) -> u16 {
    bits.into_iter()
        .enumerate()
        .map(|(i, bit)| (bit as u16) << (15 - i))
        .sum()
}

pub fn u64_to_bits(word: u64) -> [u8; 64] {
    array::from_fn(|i| {
        if 0 == (word & (0x8000000000000000 >> i)) {
            0
        } else {
            1
        }
    })
}

pub fn bits_to_u64(bits: [u8; 64]) -> u64 {
    bits.into_iter()
        .enumerate()
        .map(|(i, bit)| (bit as u64) << (63 - i))
        .sum()
}

#[cfg(test)]
mod test {
    use super::*;

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

    #[test]
    fn test_u8_to_bits() {
        let bits: [u8; 8] = u8_to_bits(0b01100011);
        assert_eq!(bits, [0, 1, 1, 0, 0, 0, 1, 1]);
    }

    #[test]
    fn test_bits_to_u8() {
        let byte = bits_to_u8([0, 1, 1, 0, 0, 0, 1, 1]);
        assert_eq!(byte, 0b01100011);
    }

    #[test]
    fn test_u16_to_bits() {
        let bits: [u8; 16] = u16_to_bits(0b1111000101100011);
        assert_eq!(bits, [1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1]);
    }

    #[test]
    fn test_bits_to_u16() {
        let word = bits_to_u16([1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1]);
        assert_eq!(word, 0b1111000101100011);
    }

    #[test]
    fn test_u64_to_bits() {
        let bits: [u8; 64] =
            u64_to_bits(0b1111000101100011_0000000000000000_1111000101100011_0000000000000000);
        assert_eq!(
            bits,
            [
                1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_bits_to_u64() {
        let word = bits_to_u64([
            1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(
            word,
            0b1111000101100011_0000000000000000_1111000101100011_0000000000000000
        );
    }
}
