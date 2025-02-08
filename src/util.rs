use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Debug;
use std::mem;

pub fn par_collect_array<const N: usize, T: Send + Sync + Debug>(
    iter: impl IntoParallelIterator<Item = T>,
) -> [T; N] {
    iter.into_par_iter()
        .collect::<Vec<_>>()
        .try_into()
        .expect("array length")
}

pub fn collect_array<const N: usize, T: Send + Sync + Debug>(
    iter: impl IntoIterator<Item = T>,
) -> [T; N] {
    iter.into_iter()
        .collect::<Vec<_>>()
        .try_into()
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

pub fn byte_to_bits(byte: u8) -> impl Iterator<Item = u8> {
    (0..8).map(move |i| if 0 == (byte & (0x80 >> i)) { 0 } else { 1 })
}

// todo

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
    fn test_byte_to_bits() {
        let bits: [u8; 8] = collect_array(byte_to_bits(0b01100011));
        assert_eq!(bits, [0, 1, 1, 0, 0, 0, 1, 1]);
    }
}
