// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Error, Result, SplitMix64};

/// A token histogram over time bins, with an infinity bin meaning "do nothing".
///
/// `edges_us` are inclusive upper edges. The first bin is `[0, edges_us[0]]`;
/// every later bin is `(edges_us[i - 1], edges_us[i]]`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Histogram {
    edges_us: Vec<u64>,
    tokens: Vec<u32>,
    infinity_tokens: u32,
    #[serde(skip)]
    remaining_tokens: Vec<u32>,
    #[serde(skip)]
    remaining_infinity_tokens: u32,
}

impl Histogram {
    /// Validate the histogram schema and token population.
    ///
    /// # Errors
    ///
    /// Returns an error when bins are empty or unordered, token dimensions
    /// differ, or either the finite or infinity population is empty.
    pub fn validate(&self) -> Result<()> {
        if self.edges_us.is_empty() {
            return Err(Error::InvalidConfig(
                "histogram must contain at least one finite bin".to_string(),
            ));
        }
        if self.tokens.len() != self.edges_us.len() {
            return Err(Error::InvalidConfig(format!(
                "histogram has {} edges but {} token counts",
                self.edges_us.len(),
                self.tokens.len()
            )));
        }
        if self
            .edges_us
            .windows(2)
            .any(|window| matches!(window, [left, right] if left >= right))
        {
            return Err(Error::InvalidConfig(
                "histogram edges must be strictly increasing".to_string(),
            ));
        }
        if !self.tokens.iter().any(|tokens| *tokens > 0) {
            return Err(Error::InvalidConfig(
                "histogram finite bins must contain at least one token".to_string(),
            ));
        }
        if self.infinity_tokens == 0 {
            return Err(Error::InvalidConfig(
                "histogram infinity bin must contain at least one token".to_string(),
            ));
        }
        Ok(())
    }

    /// Sample a bin proportional to remaining tokens.
    ///
    /// Sampling consumes one token, including when the infinity bin is
    /// selected. A finite result is sampled uniformly over every whole
    /// microsecond in that bin. `None` means the infinity bin was drawn.
    pub fn sample(&mut self, rng: &mut SplitMix64) -> Option<Duration> {
        let (delay, _) = self.sample_armed(rng)?;
        delay
    }

    /// Sample a delay while retaining the identity of the consumed token.
    ///
    /// `None` is possible only for a malformed runtime population. An
    /// infinity-bin draw is represented by a tuple whose delay is `None`.
    pub(crate) fn sample_armed(
        &mut self,
        rng: &mut SplitMix64,
    ) -> Option<(Option<Duration>, usize)> {
        self.prepare_remaining();

        let mut weights = self
            .remaining_tokens
            .iter()
            .map(|tokens| f64::from(*tokens))
            .collect::<Vec<_>>();
        weights.push(f64::from(self.remaining_infinity_tokens));
        let selected = rng.sample_index(&weights)?;

        if selected == self.remaining_tokens.len() {
            self.remaining_infinity_tokens = self.remaining_infinity_tokens.saturating_sub(1);
            return Some((None, selected));
        }

        let remaining = self.remaining_tokens.get_mut(selected)?;
        *remaining = remaining.saturating_sub(1);
        let upper = *self.edges_us.get(selected)?;
        let lower = selected
            .checked_sub(1)
            .and_then(|index| self.edges_us.get(index).copied())
            .map_or(0, |edge| edge.saturating_add(1));
        Some((
            Some(Duration::from_micros(sample_inclusive(rng, lower, upper))),
            selected,
        ))
    }

    /// Restore a token consumed by [`Self::sample_armed`].
    pub(crate) fn restore_token(&mut self, token: usize) {
        if token == self.remaining_tokens.len() {
            self.remaining_infinity_tokens = self
                .remaining_infinity_tokens
                .saturating_add(1)
                .min(self.infinity_tokens);
            return;
        }
        let Some(initial) = self.tokens.get(token).copied() else {
            return;
        };
        let Some(remaining) = self.remaining_tokens.get_mut(token) else {
            return;
        };
        *remaining = remaining.saturating_add(1).min(initial);
    }

    /// Remove one token from the bin containing `delay`.
    ///
    /// When that bin is empty, the first non-empty greater finite bin is used.
    /// The infinity bin is never used to account for observed traffic.
    pub fn remove_token(&mut self, delay: Duration) {
        self.prepare_remaining();
        if self.remaining_tokens.is_empty() {
            return;
        }

        let delay_us = u64::try_from(delay.as_micros()).unwrap_or(u64::MAX);
        let containing = self
            .edges_us
            .partition_point(|edge| *edge < delay_us)
            .min(self.remaining_tokens.len().saturating_sub(1));
        let selected = self
            .remaining_tokens
            .iter()
            .enumerate()
            .skip(containing)
            .find(|(_, tokens)| **tokens > 0)
            .map(|(index, _)| index);

        if let Some(tokens) = selected.and_then(|index| self.remaining_tokens.get_mut(index)) {
            *tokens = tokens.saturating_sub(1);
        }
    }

    /// Restore every finite token and every infinity token.
    pub fn refill(&mut self) {
        self.remaining_tokens.clone_from(&self.tokens);
        self.remaining_infinity_tokens = self.infinity_tokens;
    }

    /// Return whether every finite bin and the infinity bin are out of tokens.
    #[must_use]
    pub(crate) fn is_exhausted(&self) -> bool {
        self.remaining_tokens.len() == self.tokens.len()
            && self.remaining_tokens.iter().all(|tokens| *tokens == 0)
            && self.remaining_infinity_tokens == 0
    }

    pub(crate) const fn finite_bin_count(&self) -> usize {
        self.edges_us.len()
    }

    pub(crate) fn finite_token_count(&self) -> u64 {
        self.tokens.iter().map(|tokens| u64::from(*tokens)).sum()
    }

    pub(crate) const fn infinity_token_count(&self) -> u32 {
        self.infinity_tokens
    }

    pub(crate) fn maximum_finite_edge_us(&self) -> Option<u64> {
        self.edges_us.last().copied()
    }

    fn prepare_remaining(&mut self) {
        if self.remaining_tokens.len() != self.tokens.len() || self.is_exhausted() {
            self.refill();
        }
    }

    #[cfg(test)]
    pub(crate) fn remaining_finite_tokens(&self) -> &[u32] {
        if self.remaining_tokens.len() == self.tokens.len() {
            &self.remaining_tokens
        } else {
            &self.tokens
        }
    }
}

const fn sample_inclusive(rng: &mut SplitMix64, low: u64, high: u64) -> u64 {
    if high <= low {
        return low;
    }
    if high < u64::MAX {
        return rng.uniform_us(low, high + 1);
    }
    if low == 0 {
        return rng.next_u64();
    }

    let width = (u64::MAX - low) + 1;
    low.saturating_add(rng.uniform_us(0, width))
}

/// A row-stochastic conditional size distribution.
#[derive(Debug, Deserialize, Serialize)]
pub struct MorphingMatrix {
    buckets: Vec<u16>,
    rows: Vec<Vec<f64>>,
}

impl MorphingMatrix {
    /// Construct a matrix from inclusive bucket edges and conditional rows.
    #[must_use]
    pub const fn new(buckets: Vec<u16>, rows: Vec<Vec<f64>>) -> Self {
        Self { buckets, rows }
    }

    /// Validate bucket edges, dimensions, and row-stochastic weights.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or unordered buckets, mismatched matrix
    /// dimensions, invalid weights, or rows that do not sum to one.
    pub fn validate(&self) -> Result<()> {
        if self.buckets.is_empty() {
            return Err(Error::InvalidConfig(
                "morphing matrix must contain at least one bucket".to_string(),
            ));
        }
        if self.buckets.iter().any(|bucket| *bucket < 64) {
            return Err(Error::InvalidConfig(
                "morphing matrix bucket edges must be in [64, u16::MAX]".to_string(),
            ));
        }
        if self
            .buckets
            .windows(2)
            .any(|window| matches!(window, [left, right] if left >= right))
        {
            return Err(Error::InvalidConfig(
                "morphing matrix bucket edges must be strictly increasing".to_string(),
            ));
        }
        if self.rows.len() != self.buckets.len() {
            return Err(Error::InvalidConfig(format!(
                "morphing matrix has {} buckets but {} rows",
                self.buckets.len(),
                self.rows.len()
            )));
        }

        for (row_index, row) in self.rows.iter().enumerate() {
            if row.len() != self.buckets.len() {
                return Err(Error::InvalidConfig(format!(
                    "morphing matrix row {row_index} has {} weights; expected {}",
                    row.len(),
                    self.buckets.len()
                )));
            }

            let mut sum = 0.0;
            for weight in row {
                if !weight.is_finite() {
                    return Err(Error::InvalidConfig(format!(
                        "morphing matrix row {row_index} contains a non-finite weight"
                    )));
                }
                if *weight < 0.0 {
                    return Err(Error::InvalidConfig(format!(
                        "morphing matrix row {row_index} contains a negative weight"
                    )));
                }
                sum += weight;
            }
            let tolerance = f64::EPSILON.mul_add(4.0, 1e-9);
            if !sum.is_finite() || (sum - 1.0_f64).abs() > tolerance {
                return Err(Error::InvalidConfig(format!(
                    "morphing matrix row {row_index} sums to {sum}; expected 1"
                )));
            }
        }
        Ok(())
    }

    /// Validate a padding-only matrix against its transport ceiling.
    ///
    /// In addition to [`Self::validate`], this rejects every downward
    /// transition and requires the terminal bucket to equal the configured
    /// UDP-payload ceiling.  Runtime sampling can therefore use the stored row
    /// directly without dropping and renormalizing probability mass.
    ///
    /// # Errors
    ///
    /// Returns an error when the matrix can shrink a packet or its terminal
    /// bucket does not bind the configured ceiling.
    pub fn validate_padding_only(&self, ceiling: u16) -> Result<()> {
        self.validate()?;
        if self.buckets.last().copied() != Some(ceiling) {
            return Err(Error::InvalidConfig(format!(
                "morphing matrix terminal bucket must equal max_udp_payload_size {ceiling}"
            )));
        }
        for (row_index, row) in self.rows.iter().enumerate() {
            if row
                .iter()
                .take(row_index)
                .any(|weight| weight.abs() > 1e-12)
            {
                return Err(Error::InvalidConfig(format!(
                    "morphing matrix row {row_index} contains a downward transformation"
                )));
            }
        }
        Ok(())
    }

    /// Return the index of the inclusive bucket containing `size`.
    ///
    /// Values above the last edge map to the last bucket. An invalid empty
    /// matrix maps to index zero; [`Self::validate`] rejects that case.
    #[must_use]
    pub fn bucket_of(&self, size: u16) -> usize {
        self.buckets
            .partition_point(|bucket| *bucket < size)
            .min(self.buckets.len().saturating_sub(1))
    }

    /// Sample a target size from the stored conditional row for `size`.
    ///
    /// Callers must first use [`Self::validate_padding_only`].  No probability
    /// mass is discarded or renormalized at runtime.
    pub fn sample_target(&self, size: u16, rng: &mut SplitMix64) -> Option<u16> {
        let row = self.rows.get(self.bucket_of(size))?;
        let target = rng.sample_index(row)?;
        self.buckets.get(target).copied()
    }

    /// Largest reachable target for the conditional row containing `size`.
    #[must_use]
    pub fn maximum_target_for(&self, size: u16) -> Option<u16> {
        let row = self.rows.get(self.bucket_of(size))?;
        let index = row.iter().rposition(|weight| *weight > 0.0)?;
        self.buckets.get(index).copied()
    }

    /// Largest natural source size, beginning at `size`, whose row and every
    /// intervening row can be realized without exceeding `capacity`.
    ///
    /// This lets a transport cap frame selection before consuming RNG. It
    /// returns `None` when the current source row itself is not realizable.
    #[must_use]
    pub fn maximum_safe_source_for(&self, size: u16, capacity: u16) -> Option<u16> {
        let start = self.bucket_of(size);
        let mut safe = None;
        for index in start..self.rows.len() {
            let row = self.rows.get(index)?;
            let reachable = row
                .iter()
                .rposition(|weight| *weight > 0.0)
                .and_then(|target| self.buckets.get(target).copied())?;
            if reachable > capacity {
                break;
            }
            safe = self.buckets.get(index).copied();
        }
        safe
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{Histogram, MorphingMatrix};
    use crate::SplitMix64;

    fn histogram(value: serde_json::Value) -> Histogram {
        serde_json::from_value(value).expect("test histogram is valid JSON")
    }

    fn valid_histogram() -> Histogram {
        histogram(json!({
            "edges_us": [10, 20, 50],
            "tokens": [1, 2, 3],
            "infinity_tokens": 4
        }))
    }

    fn valid_matrix() -> MorphingMatrix {
        MorphingMatrix::new(
            vec![64, 100, 200],
            vec![
                vec![0.2, 0.3, 0.5],
                vec![0.1, 0.6, 0.3],
                vec![0.0, 0.0, 1.0],
            ],
        )
    }

    #[test]
    fn reachable_target_and_safe_source_are_row_specific() {
        let matrix = MorphingMatrix::new(
            vec![64, 100, 200],
            vec![
                vec![1.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0],
                vec![0.0, 0.0, 1.0],
            ],
        );
        matrix.validate_padding_only(200).expect("valid matrix");
        assert_eq!(matrix.maximum_target_for(63), Some(64));
        assert_eq!(matrix.maximum_target_for(80), Some(100));
        assert_eq!(matrix.maximum_target_for(150), Some(200));
        assert_eq!(matrix.maximum_safe_source_for(63, 100), Some(100));
        assert_eq!(matrix.maximum_safe_source_for(80, 100), Some(100));
        assert_eq!(matrix.maximum_safe_source_for(150, 100), None);
    }

    #[test]
    fn histogram_validation_accepts_the_schema() {
        assert!(valid_histogram().validate().is_ok());
        assert!(
            histogram(json!({
                "edges_us": [0, 1],
                "tokens": [1, 1],
                "infinity_tokens": 1
            }))
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn histogram_validation_rejects_every_invalid_shape() {
        let invalid = [
            json!({"edges_us": [], "tokens": [], "infinity_tokens": 1}),
            json!({"edges_us": [10, 20], "tokens": [1], "infinity_tokens": 1}),
            json!({"edges_us": [10, 10], "tokens": [1, 1], "infinity_tokens": 1}),
            json!({"edges_us": [20, 10], "tokens": [1, 1], "infinity_tokens": 1}),
            json!({"edges_us": [10, 20], "tokens": [0, 0], "infinity_tokens": 1}),
            json!({"edges_us": [10, 20], "tokens": [1, 1], "infinity_tokens": 0}),
        ];
        for value in invalid {
            assert!(histogram(value).validate().is_err());
        }
    }

    #[test]
    fn finite_sampling_consumes_tokens_and_uses_inclusive_edges() {
        let mut first = histogram(json!({
            "edges_us": [3, 7],
            "tokens": [1, 0],
            "infinity_tokens": 0
        }));
        let mut second = histogram(json!({
            "edges_us": [3, 7],
            "tokens": [0, 1],
            "infinity_tokens": 0
        }));

        assert_eq!(first.sample(&mut SplitMix64::new(5)), Some(Duration::ZERO));
        assert_eq!(first.remaining_tokens, [0, 0]);
        assert!(first.is_exhausted());

        assert_eq!(
            second.sample(&mut SplitMix64::new(5)),
            Some(Duration::from_micros(4))
        );
        assert_eq!(second.remaining_tokens, [0, 0]);
        assert!(second.is_exhausted());
    }

    #[test]
    fn infinity_sampling_consumes_its_token() {
        let mut histogram = histogram(json!({
            "edges_us": [10],
            "tokens": [1],
            "infinity_tokens": 10
        }));
        let mut rng = SplitMix64::new(1);

        assert_eq!(histogram.sample(&mut rng), None);
        assert_eq!(histogram.remaining_tokens, [1]);
        assert_eq!(histogram.remaining_infinity_tokens, 9);
    }

    #[test]
    fn refill_restores_finite_and_infinity_populations() {
        let mut histogram = valid_histogram();
        histogram.refill();
        histogram.remaining_tokens = vec![0, 1, 0];
        histogram.remaining_infinity_tokens = 0;

        histogram.refill();

        assert_eq!(histogram.remaining_tokens, [1, 2, 3]);
        assert_eq!(histogram.remaining_infinity_tokens, 4);
        assert!(!histogram.is_exhausted());
    }

    #[test]
    fn sampling_uses_remaining_infinity_mass_before_refilling() {
        let mut histogram = histogram(json!({
            "edges_us": [0],
            "tokens": [1],
            "infinity_tokens": 2
        }));
        histogram.refill();
        histogram.remaining_tokens[0] = 0;
        histogram.remaining_infinity_tokens = 1;

        let sampled = histogram.sample(&mut SplitMix64::new(0));

        assert_eq!(sampled, None);
        assert_eq!(histogram.remaining_tokens, [0]);
        assert_eq!(histogram.remaining_infinity_tokens, 0);
        assert!(histogram.is_exhausted());

        let _second_sample = histogram.sample(&mut SplitMix64::new(0));
        assert_eq!(
            histogram.remaining_tokens.iter().sum::<u32>() + histogram.remaining_infinity_tokens,
            2
        );
        assert!(!histogram.is_exhausted());
    }

    #[test]
    fn remove_token_uses_inclusive_bins_and_clamps_the_tail() {
        let mut histogram = histogram(json!({
            "edges_us": [10, 20],
            "tokens": [2, 2],
            "infinity_tokens": 1
        }));

        histogram.remove_token(Duration::from_micros(10));
        assert_eq!(histogram.remaining_tokens, [1, 2]);
        histogram.remove_token(Duration::from_micros(11));
        assert_eq!(histogram.remaining_tokens, [1, 1]);
        histogram.remove_token(Duration::from_millis(1));
        assert_eq!(histogram.remaining_tokens, [1, 0]);
    }

    #[test]
    fn remove_token_falls_forward_to_the_next_nonempty_bin() {
        let mut histogram = histogram(json!({
            "edges_us": [10, 20, 30],
            "tokens": [1, 0, 1],
            "infinity_tokens": 1
        }));

        histogram.remove_token(Duration::from_micros(15));
        assert_eq!(histogram.remaining_tokens, [1, 0, 0]);
        histogram.remove_token(Duration::from_micros(15));
        assert_eq!(histogram.remaining_tokens, [1, 0, 0]);
        assert!(!histogram.is_exhausted());
    }

    #[test]
    fn armed_sample_can_be_restored_before_observed_delay_removal() {
        let mut histogram = histogram(json!({
            "edges_us": [0, 10],
            "tokens": [1, 1],
            "infinity_tokens": 1
        }));
        let mut rng = SplitMix64::new(3);
        histogram.refill();
        let before = (
            histogram.remaining_tokens.clone(),
            histogram.remaining_infinity_tokens,
        );

        let (_, token) = histogram.sample_armed(&mut rng).expect("sample");
        histogram.restore_token(token);

        assert_eq!(
            (
                histogram.remaining_tokens.clone(),
                histogram.remaining_infinity_tokens,
            ),
            before
        );
        histogram.remove_token(Duration::from_micros(1));
        assert_eq!(histogram.remaining_tokens.iter().sum::<u32>(), 1);
    }

    #[test]
    fn serialization_omits_runtime_token_state() {
        let mut histogram = valid_histogram();
        let _sample = histogram.sample(&mut SplitMix64::new(1));

        let serialized = serde_json::to_value(histogram).expect("histogram serializes");

        assert_eq!(
            serialized,
            json!({
                "edges_us": [10, 20, 50],
                "tokens": [1, 2, 3],
                "infinity_tokens": 4
            })
        );
    }

    #[test]
    fn morphing_validation_accepts_a_row_stochastic_matrix() {
        assert!(valid_matrix().validate().is_ok());
        let tolerance = MorphingMatrix::new(vec![64], vec![vec![1.0 + 1e-9]]);
        assert!(tolerance.validate().is_ok());
    }

    #[test]
    fn morphing_validation_rejects_empty_and_bad_bucket_edges() {
        let invalid = [
            MorphingMatrix::new(vec![], vec![]),
            MorphingMatrix::new(vec![63], vec![vec![1.0]]),
            MorphingMatrix::new(vec![64, 64], vec![vec![0.5, 0.5], vec![0.5, 0.5]]),
            MorphingMatrix::new(vec![100, 64], vec![vec![0.5, 0.5], vec![0.5, 0.5]]),
        ];
        for matrix in invalid {
            assert!(matrix.validate().is_err());
        }
    }

    #[test]
    fn morphing_validation_rejects_bad_dimensions() {
        let invalid = [
            MorphingMatrix::new(vec![64, 100], vec![vec![0.5, 0.5]]),
            MorphingMatrix::new(vec![64, 100], vec![vec![1.0], vec![0.5, 0.5]]),
            MorphingMatrix::new(vec![64], vec![vec![]]),
        ];
        for matrix in invalid {
            assert!(matrix.validate().is_err());
        }
    }

    #[test]
    fn morphing_validation_rejects_invalid_weights_and_sums() {
        let invalid = [
            MorphingMatrix::new(vec![64], vec![vec![-1.0]]),
            MorphingMatrix::new(vec![64], vec![vec![f64::NAN]]),
            MorphingMatrix::new(vec![64], vec![vec![f64::INFINITY]]),
            MorphingMatrix::new(vec![64], vec![vec![0.5]]),
            MorphingMatrix::new(vec![64], vec![vec![1.0 + 1.1e-9]]),
        ];
        for matrix in invalid {
            assert!(matrix.validate().is_err());
        }
    }

    #[test]
    fn bucket_lookup_uses_inclusive_upper_edges_and_clamps() {
        let matrix = valid_matrix();
        assert_eq!(matrix.bucket_of(0), 0);
        assert_eq!(matrix.bucket_of(64), 0);
        assert_eq!(matrix.bucket_of(65), 1);
        assert_eq!(matrix.bucket_of(100), 1);
        assert_eq!(matrix.bucket_of(101), 2);
        assert_eq!(matrix.bucket_of(u16::MAX), 2);
        assert_eq!(MorphingMatrix::new(vec![], vec![]).bucket_of(100), 0);
    }

    #[test]
    fn padding_only_validation_rejects_downward_mass_and_wrong_ceiling() {
        let matrix = MorphingMatrix::new(
            vec![64, 100, 200],
            vec![
                vec![1.0, 0.0, 0.0],
                vec![0.9, 0.0, 0.1],
                vec![0.9, 0.1, 0.0],
            ],
        );
        assert!(matrix.validate_padding_only(200).is_err());
        let strict = MorphingMatrix::new(
            vec![64, 100, 200],
            vec![
                vec![0.2, 0.3, 0.5],
                vec![0.0, 0.6, 0.4],
                vec![0.0, 0.0, 1.0],
            ],
        );
        assert!(strict.validate_padding_only(200).is_ok());
        assert!(strict.validate_padding_only(1_200).is_err());
    }

    #[test]
    fn target_sampling_uses_the_stored_padding_only_row() {
        let matrix = MorphingMatrix::new(
            vec![64, 100, 200],
            vec![
                vec![0.2, 0.3, 0.5],
                vec![0.0, 0.6, 0.4],
                vec![0.0, 0.0, 1.0],
            ],
        );
        let mut rng = SplitMix64::new(0xCAFE);
        let samples = std::array::from_fn::<_, 8, _>(|_| matrix.sample_target(65, &mut rng));
        assert_eq!(
            samples,
            [
                Some(200),
                Some(200),
                Some(100),
                Some(100),
                Some(100),
                Some(100),
                Some(200),
                Some(200),
            ]
        );
    }
}
