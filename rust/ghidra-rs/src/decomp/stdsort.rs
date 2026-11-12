//! A port of libstdc++'s `std::sort` (introsort: median-of-three quicksort, heapsort past the
//! depth limit, a final insertion sort), for sorts whose keys tie in the C++.
//!
//! `std::sort` is not stable, so equal keys come out in an order only its exact algorithm
//! decides; where that order reaches the output (e.g. `Funcdata::sortCallSpecs`, whose op order
//! keys repeat in long blocks), Rust's sorts would differ. The reference is built with g++, so
//! this follows `bits/stl_algo.h` and `bits/stl_heap.h`.

const THRESHOLD: usize = 16;

/// `std::sort(v.begin(), v.end(), less)`.
pub(crate) fn sort<T: Copy>(v: &mut [T], less: impl Fn(&T, &T) -> bool) {
    if v.len() > 1 {
        let depth = 2 * (usize::BITS - 1 - v.len().leading_zeros()) as usize;
        introsort_loop(v, depth, &less);
        final_insertion_sort(v, &less);
    }
}

fn introsort_loop<T: Copy>(mut v: &mut [T], mut depth: usize, less: &impl Fn(&T, &T) -> bool) {
    while v.len() > THRESHOLD {
        if depth == 0 {
            heap_sort(v, less);
            return;
        }
        depth -= 1;
        let cut = partition_pivot(v, less);
        let (left, right) = v.split_at_mut(cut);
        introsort_loop(right, depth, less);
        v = left;
    }
}

/// `__unguarded_partition_pivot`: the median of `v[1]`, the middle and the last element moves to
/// `v[0]`, then `v[1..]` is partitioned around it; returns the cut.
fn partition_pivot<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) -> usize {
    let (mid, last) = (v.len() / 2, v.len() - 1);
    let (a, b, c) = (1, mid, last);
    let median = if less(&v[a], &v[b]) {
        if less(&v[b], &v[c]) {
            b
        } else if less(&v[a], &v[c]) {
            c
        } else {
            a
        }
    } else if less(&v[a], &v[c]) {
        a
    } else if less(&v[b], &v[c]) {
        c
    } else {
        b
    };
    v.swap(0, median);
    let (mut first, mut last) = (1, v.len());
    loop {
        while less(&v[first], &v[0]) {
            first += 1;
        }
        last -= 1;
        while less(&v[0], &v[last]) {
            last -= 1;
        }
        if first >= last {
            return first;
        }
        v.swap(first, last);
        first += 1;
    }
}

fn final_insertion_sort<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    if v.len() > THRESHOLD {
        insertion_sort(&mut v[..THRESHOLD], less);
        for i in THRESHOLD..v.len() {
            linear_insert(v, i, less);
        }
    } else {
        insertion_sort(v, less);
    }
}

fn insertion_sort<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    for i in 1..v.len() {
        if less(&v[i], &v[0]) {
            v[..=i].rotate_right(1);
        } else {
            linear_insert(v, i, less);
        }
    }
}

/// `__unguarded_linear_insert`: move `v[i]` down past the larger elements before it.
fn linear_insert<T: Copy>(v: &mut [T], mut i: usize, less: &impl Fn(&T, &T) -> bool) {
    let val = v[i];
    while less(&val, &v[i - 1]) {
        v[i] = v[i - 1];
        i -= 1;
    }
    v[i] = val;
}

/// `std::partial_sort(first, last, last)`: make a heap, then pop it.
fn heap_sort<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    let len = v.len();
    for parent in (0..=(len - 2) / 2).rev() {
        adjust_heap(v, parent, len, v[parent], less);
    }
    for last in (1..len).rev() {
        let val = v[last];
        v[last] = v[0];
        adjust_heap(v, 0, last, val, less);
    }
}

/// `__adjust_heap` with `__push_heap`.
fn adjust_heap<T: Copy>(v: &mut [T], mut hole: usize, len: usize, val: T, less: &impl Fn(&T, &T) -> bool) {
    let top = hole;
    let mut child = hole;
    while child < (len - 1) / 2 {
        child = 2 * (child + 1);
        if less(&v[child], &v[child - 1]) {
            child -= 1;
        }
        v[hole] = v[child];
        hole = child;
    }
    if len.is_multiple_of(2) && child == (len - 2) / 2 {
        child = 2 * (child + 1);
        v[hole] = v[child - 1];
        hole = child - 1;
    }
    let mut parent = hole.wrapping_sub(1) / 2;
    while hole > top && less(&v[parent], &val) {
        v[hole] = v[parent];
        hole = parent;
        parent = hole.wrapping_sub(1) / 2;
    }
    v[hole] = val;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_by_key() {
        let mut seed = 12345u32;
        let mut v: Vec<(u32, usize)> = (0..1000)
            .map(|i| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                ((seed >> 16) % 50, i)
            })
            .collect();
        sort(&mut v, |a, b| a.0 < b.0);
        assert!(v.windows(2).all(|w| w[0].0 <= w[1].0));
        let mut ids: Vec<usize> = v.iter().map(|x| x.1).collect();
        ids.sort_unstable();
        assert!(ids.iter().enumerate().all(|(i, &x)| i == x));
        // the depth limit forces heapsort on this many equal-key runs too
        let mut w: Vec<u32> = (0..300).rev().collect();
        sort(&mut w, |a, b| a < b);
        assert!(w.windows(2).all(|p| p[0] < p[1]));
    }
}
