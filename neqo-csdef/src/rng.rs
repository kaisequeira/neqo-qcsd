// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Version-stable PRNG used to keep research traces reproducible.
#[derive(Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a deterministic stream from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Return the next raw value in the stream.
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// Sample an integer from `1..=maximum`.
    ///
    /// # Panics
    ///
    /// Panics when `maximum` is zero. Validated FRONT configurations always
    /// provide a positive maximum.
    pub fn range_inclusive(&mut self, maximum: u32) -> u32 {
        let range = u64::from(maximum);
        let rejection = u64::MAX - (u64::MAX % range);
        loop {
            let value = self.next_u64();
            if value < rejection {
                return u32::try_from(value % range).unwrap_or(u32::MAX) + 1;
            }
        }
    }

    /// Sample a floating-point value strictly between zero and one.
    pub fn unit_open(&mut self) -> f64 {
        let value = self.next_u64() >> 11;
        let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
        let low = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX);
        let value = f64::from(high).mul_add(4_294_967_296.0, f64::from(low));
        (value + 0.5) / 9_007_199_254_740_992.0
    }

    /// Sample a floating-point value from `[minimum, maximum)`.
    pub fn range_f64(&mut self, minimum: f64, maximum: f64) -> f64 {
        self.unit_open().mul_add(maximum - minimum, minimum)
    }

    /// Index into `weights` proportional to their values.
    ///
    /// Returns `None` when the slice is empty, contains a negative or
    /// non-finite value, or sums to zero.
    pub fn sample_index(&mut self, weights: &[f64]) -> Option<usize> {
        if weights.is_empty()
            || weights
                .iter()
                .any(|weight| !weight.is_finite() || *weight < 0.0)
        {
            return None;
        }

        let total = weights.iter().sum::<f64>();
        if !total.is_finite() || total <= 0.0 {
            return None;
        }

        let target = self.unit_open() * total;
        let mut cumulative = 0.0;
        let mut last_positive = None;
        for (index, weight) in weights.iter().copied().enumerate() {
            if weight > 0.0 {
                last_positive = Some(index);
            }
            cumulative += weight;
            if target < cumulative {
                return Some(index);
            }
        }

        // Floating-point addition can round the final cumulative value below
        // `total`; the final positive bucket owns that residual.
        last_positive
    }

    /// Sample a whole-microsecond value uniformly from `[low, high)`.
    ///
    /// Returns `low` without consuming a draw when `high <= low`.
    pub const fn uniform_us(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }

        low.saturating_add(self.uniform_below(high - low))
    }

    const fn uniform_below(&mut self, range: u64) -> u64 {
        let rejection = u64::MAX - (u64::MAX % range);
        loop {
            let value = self.next_u64();
            if value < rejection {
                return value % range;
            }
        }
    }
}

/// Derive an independent stream from the run seed for one defense.
///
/// Domain separation combines the 64-bit FNV-1a hash of `domain` with `seed`
/// using XOR before initialising [`SplitMix64`].
#[must_use]
pub fn derive(seed: u64, domain: &str) -> SplitMix64 {
    const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in domain.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    SplitMix64::new(seed ^ hash)
}

#[cfg(test)]
mod tests {
    use super::{SplitMix64, derive};

    #[test]
    fn raw_stream_is_pinned() {
        let mut rng = SplitMix64::new(42);
        assert_eq!(
            [
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
            ],
            [
                13_679_457_532_755_275_413,
                2_949_826_092_126_892_291,
                5_139_283_748_462_763_858,
                6_349_198_060_258_255_764,
            ]
        );
    }

    #[test]
    fn proportional_index_sampling_is_pinned() {
        let mut rng = SplitMix64::new(0x000A_11CE);
        let weights = [0.0, 1.0, 3.0, 6.0];
        let samples = std::array::from_fn::<_, 8, _>(|_| rng.sample_index(&weights));
        assert_eq!(
            samples,
            [
                Some(3),
                Some(3),
                Some(2),
                Some(3),
                Some(3),
                Some(2),
                Some(3),
                Some(3),
            ]
        );
    }

    #[test]
    fn proportional_index_rejects_invalid_distributions_without_drawing() {
        let invalid = [
            &[][..],
            &[0.0, 0.0][..],
            &[1.0, -1.0][..],
            &[1.0, f64::NAN][..],
            &[1.0, f64::INFINITY][..],
        ];
        for weights in invalid {
            let mut rejected = SplitMix64::new(7);
            assert_eq!(rejected.sample_index(weights), None);
            let mut untouched = SplitMix64::new(7);
            assert_eq!(rejected.next_u64(), untouched.next_u64());
        }
    }

    #[test]
    fn half_open_microsecond_sampling_is_pinned_and_bounded() {
        let mut rng = SplitMix64::new(99);
        let samples = std::array::from_fn::<_, 8, _>(|_| rng.uniform_us(1_000, 2_000));
        assert_eq!(
            samples,
            [1_403, 1_564, 1_627, 1_807, 1_076, 1_699, 1_635, 1_595]
        );
        assert!(samples.iter().all(|sample| (1_000..2_000).contains(sample)));
    }

    #[test]
    fn degenerate_uniform_ranges_do_not_draw() {
        let mut degenerate = SplitMix64::new(123);
        assert_eq!(degenerate.uniform_us(500, 500), 500);
        assert_eq!(degenerate.uniform_us(500, 499), 500);

        let mut untouched = SplitMix64::new(123);
        assert_eq!(degenerate.next_u64(), untouched.next_u64());
    }

    #[test]
    fn derived_streams_are_domain_separated_and_pinned() {
        let mut wtf_pad = derive(42, "wtf-pad");
        let mut morphing = derive(42, "traffic-morphing");
        let mut empty = derive(42, "");

        assert_eq!(wtf_pad.next_u64(), 10_771_209_204_917_679_290);
        assert_eq!(morphing.next_u64(), 17_217_325_775_348_879_809);
        assert_eq!(empty.next_u64(), 16_989_316_241_837_898_229);
    }
}
