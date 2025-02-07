use rayon::iter::IntoParallelIterator;
use std::fmt::Debug;
use std::mem;

pub fn collect_array<const N: usize, T: Send + Sync + Debug>(
    iter: impl IntoParallelIterator<Item = T>,
) -> [T; N] {
    iter.into_par_iter()
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
