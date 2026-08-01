// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::Path,
    time::Duration,
};

use serde::Deserialize;

use super::{Defense, DefenseDiagnostics, DefenseMode, DefenseSignal, EventOutcome, SignalKind};
use crate::{
    Direction, Error, MorphingMatrix, Packet, QcsdDatagramClass, Result, SplitMix64,
    TrafficMorphingBypassReason, TrafficMorphingConfig, TrafficMorphingOutcome, derive,
};

const SCHEMA_VERSION: u32 = 2;
const ADAPTATION: &str = "qcsd-client-only";
const FLOAT_TOLERANCE: f64 = 1e-8;
const PARTS_PER_MILLION: u64 = 1_000_000;

#[derive(Debug)]
struct DistributionDistance {
    buckets: Vec<u16>,
    target_ppm: Vec<u64>,
    observed: Vec<u64>,
}

impl DistributionDistance {
    fn new(buckets: &[u16], target: &[f64]) -> Self {
        Self {
            buckets: buckets.to_vec(),
            target_ppm: distribution_ppm(target),
            observed: vec![0; buckets.len()],
        }
    }

    fn observe(&mut self, size: u16) {
        let index = self
            .buckets
            .partition_point(|bucket| *bucket < size)
            .min(self.observed.len().saturating_sub(1));
        if let Some(count) = self.observed.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    fn l1_ppm(&self) -> u64 {
        let total = self
            .observed
            .iter()
            .fold(0_u128, |sum, count| sum.saturating_add(u128::from(*count)));
        if total == 0 {
            return 0;
        }

        let numerator =
            self.observed
                .iter()
                .zip(&self.target_ppm)
                .fold(0_u128, |sum, (count, target_ppm)| {
                    let observed_scaled =
                        u128::from(*count).saturating_mul(u128::from(PARTS_PER_MILLION));
                    let target_scaled = u128::from(*target_ppm).saturating_mul(total);
                    sum.saturating_add(observed_scaled.abs_diff(target_scaled))
                });
        let rounded = numerator.saturating_add(total / 2) / total;
        u64::try_from(rounded).unwrap_or(u64::MAX)
    }
}

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "validated probabilities are normalized into the closed integer ppm range"
)]
fn distribution_ppm(distribution: &[f64]) -> Vec<u64> {
    let total = distribution.iter().sum::<f64>();
    let mut scaled: Vec<_> = distribution
        .iter()
        .enumerate()
        .map(|(index, probability)| {
            let exact = probability / total * PARTS_PER_MILLION as f64;
            let floor = exact.floor() as u64;
            (index, floor, exact - floor as f64)
        })
        .collect();
    let assigned = scaled
        .iter()
        .fold(0_u64, |sum, (_, floor, _)| sum.saturating_add(*floor));
    let remainder =
        usize::try_from(PARTS_PER_MILLION.saturating_sub(assigned)).unwrap_or(usize::MAX);
    scaled.sort_by(|left, right| {
        right
            .2
            .total_cmp(&left.2)
            .then_with(|| left.0.cmp(&right.0))
    });
    for (_, value, _) in scaled.iter_mut().take(remainder) {
        *value = value.saturating_add(1);
    }
    scaled.sort_unstable_by_key(|(index, _, _)| *index);
    scaled.into_iter().map(|(_, value, _)| value).collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixFile {
    adaptation: String,
    buckets: Vec<u16>,
    generated_by: String,
    paper_equivalent: bool,
    profiles: Vec<MatrixProfile>,
    schema_version: u32,
    udp_payload_ceiling: u16,
}

impl MatrixFile {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&input)?)
    }

    fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported Traffic Morphing matrix schema version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.adaptation != ADAPTATION || self.paper_equivalent {
            return Err(Error::InvalidConfig(
                "Traffic Morphing parameters must declare the QCSD client-only adaptation".into(),
            ));
        }
        if self.generated_by.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "Traffic Morphing matrix provenance fields must not be empty".into(),
            ));
        }
        if self.udp_payload_ceiling != max_udp_payload_size {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing udp_payload_ceiling {} does not match max_udp_payload_size {max_udp_payload_size}",
                self.udp_payload_ceiling
            )));
        }
        if self.profiles.is_empty() {
            return Err(Error::InvalidConfig(
                "Traffic Morphing bundle must contain at least one profile".into(),
            ));
        }
        let mut sources = HashSet::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            profile.validate(&self.buckets, max_udp_payload_size)?;
            if !sources.insert(profile.source.as_str()) {
                return Err(Error::InvalidConfig(format!(
                    "Traffic Morphing bundle contains duplicate source profile {:?}",
                    profile.source
                )));
            }
        }
        Ok(())
    }

    fn profile(&self, workload_id: &str, max_udp_payload_size: u16) -> Result<&MatrixProfile> {
        self.validate(max_udp_payload_size)?;
        let mut matching = self
            .profiles
            .iter()
            .filter(|profile| profile.source == workload_id);
        let Some(profile) = matching.next() else {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing bundle has no profile for workload_id {workload_id:?}"
            )));
        };
        if matching.next().is_some() {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing bundle has multiple profiles for workload_id {workload_id:?}"
            )));
        }
        Ok(profile)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixProfile {
    incoming: MatrixDirection,
    outgoing: MatrixDirection,
    source: String,
    target: String,
}

impl MatrixProfile {
    fn validate(&self, buckets: &[u16], max_udp_payload_size: u16) -> Result<()> {
        if self.source.trim().is_empty()
            || self.target.trim().is_empty()
            || self.source.trim() != self.source
            || self.target.trim() != self.target
        {
            return Err(Error::InvalidConfig(
                "Traffic Morphing profile source and target must be non-empty and have no surrounding whitespace".into(),
            ));
        }
        if self.source == self.target {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing profile source and target must differ: {:?}",
                self.source
            )));
        }
        self.outgoing
            .validate("outgoing", buckets, max_udp_payload_size)?;
        self.incoming
            .validate("incoming", buckets, max_udp_payload_size)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixDirection {
    expected_added_bytes: f64,
    l1_distance: f64,
    realized_distribution: Vec<f64>,
    rows: Vec<Vec<f64>>,
    source_distribution: Vec<f64>,
    target_distribution: Vec<f64>,
}

impl MatrixDirection {
    fn matrix(&self, buckets: &[u16]) -> MorphingMatrix {
        MorphingMatrix::new(buckets.to_vec(), self.rows.clone())
    }

    fn validate(&self, label: &str, buckets: &[u16], ceiling: u16) -> Result<()> {
        let matrix = self.matrix(buckets);
        matrix.validate_padding_only(ceiling)?;
        let count = buckets.len();
        validate_distribution(&self.source_distribution, count, label, "source")?;
        validate_distribution(&self.target_distribution, count, label, "target")?;
        validate_distribution(&self.realized_distribution, count, label, "realized")?;

        let mut realized = vec![0.0; count];
        for (row_index, row) in self.rows.iter().enumerate() {
            for (column, weight) in row.iter().enumerate() {
                realized[column] += self.source_distribution[row_index] * weight;
            }
        }
        if realized
            .iter()
            .zip(&self.realized_distribution)
            .any(|(actual, claimed)| (actual - claimed).abs() > FLOAT_TOLERANCE)
        {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing {label} realized distribution does not match its matrix"
            )));
        }
        let l1 = realized
            .iter()
            .zip(&self.target_distribution)
            .map(|(actual, target)| (actual - target).abs())
            .sum::<f64>();
        if !self.l1_distance.is_finite()
            || self.l1_distance < 0.0
            || (l1 - self.l1_distance).abs() > FLOAT_TOLERANCE
        {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing {label} l1_distance does not match its distributions"
            )));
        }
        let expected = self
            .rows
            .iter()
            .enumerate()
            .map(|(row_index, row)| {
                row.iter()
                    .enumerate()
                    .map(|(column, weight)| {
                        self.source_distribution[row_index]
                            * weight
                            * f64::from(buckets[column].saturating_sub(buckets[row_index]))
                    })
                    .sum::<f64>()
            })
            .sum::<f64>();
        if !self.expected_added_bytes.is_finite()
            || self.expected_added_bytes < 0.0
            || (expected - self.expected_added_bytes).abs() > FLOAT_TOLERANCE
        {
            return Err(Error::InvalidConfig(format!(
                "Traffic Morphing {label} expected_added_bytes does not match its matrix"
            )));
        }
        Ok(())
    }
}

fn validate_distribution(values: &[f64], count: usize, direction: &str, label: &str) -> Result<()> {
    if values.len() != count
        || values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err(Error::InvalidConfig(format!(
            "Traffic Morphing {direction} {label} distribution is invalid"
        )));
    }
    let sum = values.iter().sum::<f64>();
    if (sum - 1.0).abs() > FLOAT_TOLERANCE {
        return Err(Error::InvalidConfig(format!(
            "Traffic Morphing {direction} {label} distribution sums to {sum}; expected 1"
        )));
    }
    Ok(())
}

/// Allocation-free same-datagram sampler owned by one QUIC connection.
#[derive(Debug)]
pub struct TrafficMorphingEgress {
    matrix: MorphingMatrix,
    rng: SplitMix64,
}

impl TrafficMorphingEgress {
    /// Load and validate the strict egress matrix.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid configuration or parameter artifact.
    pub fn new(
        config: &TrafficMorphingConfig,
        seed: u64,
        max_udp_payload_size: u16,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file = MatrixFile::from_file(&config.matrix)?;
        let profile = file.profile(&config.workload_id, max_udp_payload_size)?;
        Ok(Self {
            matrix: profile.outgoing.matrix(&file.buckets),
            rng: derive(seed, "traffic-morphing-egress"),
        })
    }

    /// Parse a strict egress matrix from JSON, primarily for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid configuration or parameter artifact.
    pub fn from_json(
        config: &TrafficMorphingConfig,
        seed: u64,
        max_udp_payload_size: u16,
        input: &str,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file: MatrixFile = serde_json::from_str(input)?;
        let profile = file.profile(&config.workload_id, max_udp_payload_size)?;
        Ok(Self {
            matrix: profile.outgoing.matrix(&file.buckets),
            rng: derive(seed, "traffic-morphing-egress"),
        })
    }

    /// Sample the exact UDP-payload target for one natural datagram.
    #[must_use]
    pub fn sample_target(&mut self, natural_size: u16) -> Option<u16> {
        self.matrix.sample_target(natural_size, &mut self.rng)
    }

    /// Largest target reachable from the row containing `natural_size`.
    #[must_use]
    pub fn maximum_target_for(&self, natural_size: u16) -> Option<u16> {
        self.matrix.maximum_target_for(natural_size)
    }

    /// Largest source size that remains within rows realizable at `capacity`.
    #[must_use]
    pub fn maximum_safe_source_for(&self, natural_size: u16, capacity: u16) -> Option<u16> {
        self.matrix.maximum_safe_source_for(natural_size, capacity)
    }
}

/// Client-side Traffic Morphing controller.
///
/// Client egress is transformed in place by [`TrafficMorphingEgress`].  This
/// controller owns only the explicitly approximate ingress target-realization
/// layer, which asks the existing QCSD receive-credit/chaff path for additional
/// observed bytes.
#[derive(Debug)]
pub struct TrafficMorphing {
    incoming: MorphingMatrix,
    egress_distribution: DistributionDistance,
    ingress_distribution: DistributionDistance,
    rng: SplitMix64,
    ingress_packet_size: u16,
    max_ingress_deficit_bytes: u64,
    ingress_deficit: u64,
    awaiting_ingress: VecDeque<Packet>,
    ingress_requested: u64,
    ingress_outstanding: u64,
    ingress_credit_outstanding: u64,
    ingress_received: u64,
    ingress_shortfall: u64,
    egress_packets: u64,
    egress_source_bytes: u64,
    egress_target_bytes: u64,
    egress_bypasses: u64,
    egress_pacing_bypasses: u64,
    egress_congestion_bypasses: u64,
    egress_coalesced_bypasses: u64,
    egress_invalid_size_bypasses: u64,
    egress_target_selection_bypasses: u64,
    pending: VecDeque<Packet>,
    suppressed_cover_feedback: u64,
    application_complete: bool,
}

impl TrafficMorphing {
    /// Load a version-two Traffic Morphing parameter artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, provenance, distributions,
    /// matrices, or transport binding.
    pub fn new(
        config: &TrafficMorphingConfig,
        seed: u64,
        max_udp_payload_size: u16,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file = MatrixFile::from_file(&config.matrix)?;
        Self::from_parameters(config, seed, max_udp_payload_size, &file)
    }

    /// Parse a version-two parameter artifact from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, provenance, distributions,
    /// matrices, or transport binding.
    pub fn from_json(
        config: &TrafficMorphingConfig,
        seed: u64,
        max_udp_payload_size: u16,
        input: &str,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file: MatrixFile = serde_json::from_str(input)?;
        Self::from_parameters(config, seed, max_udp_payload_size, &file)
    }

    fn from_parameters(
        config: &TrafficMorphingConfig,
        seed: u64,
        max_udp_payload_size: u16,
        file: &MatrixFile,
    ) -> Result<Self> {
        let profile = file.profile(&config.workload_id, max_udp_payload_size)?;
        Ok(Self {
            incoming: profile.incoming.matrix(&file.buckets),
            egress_distribution: DistributionDistance::new(
                &file.buckets,
                &profile.outgoing.target_distribution,
            ),
            ingress_distribution: DistributionDistance::new(
                &file.buckets,
                &profile.incoming.target_distribution,
            ),
            rng: derive(seed, "traffic-morphing-ingress"),
            ingress_packet_size: config.ingress_packet_size,
            max_ingress_deficit_bytes: config.max_ingress_deficit_bytes,
            ingress_deficit: 0,
            awaiting_ingress: VecDeque::new(),
            ingress_requested: 0,
            ingress_outstanding: 0,
            ingress_credit_outstanding: 0,
            ingress_received: 0,
            ingress_shortfall: 0,
            egress_packets: 0,
            egress_source_bytes: 0,
            egress_target_bytes: 0,
            egress_bypasses: 0,
            egress_pacing_bypasses: 0,
            egress_congestion_bypasses: 0,
            egress_coalesced_bypasses: 0,
            egress_invalid_size_bypasses: 0,
            egress_target_selection_bypasses: 0,
            pending: VecDeque::new(),
            suppressed_cover_feedback: 0,
            application_complete: false,
        })
    }

    fn on_incoming_wire(&mut self, at: Duration, length: u16) {
        if self.application_complete {
            return;
        }
        let target = self
            .incoming
            .sample_target(length, &mut self.rng)
            .unwrap_or(length);
        let desired = u64::from(target.saturating_sub(length));
        let available = self
            .max_ingress_deficit_bytes
            .saturating_sub(self.unresolved_ingress_bytes());
        let admitted = desired.min(available);
        self.ingress_deficit = self.ingress_deficit.saturating_add(admitted);
        self.ingress_shortfall = self
            .ingress_shortfall
            .saturating_add(desired.saturating_sub(admitted));
        self.queue_ingress_deficit(at);
        debug_assert!(self.unresolved_ingress_bytes() <= self.max_ingress_deficit_bytes);
    }

    /// Total admitted target bytes that have not been observed or abandoned.
    ///
    /// Each desired byte belongs to exactly one stage. Resolved receive credit
    /// is metadata for `ingress_outstanding`, not a second copy of that debt.
    fn unresolved_ingress_bytes(&self) -> u64 {
        self.pending.iter().chain(&self.awaiting_ingress).fold(
            self.ingress_deficit
                .saturating_add(self.ingress_outstanding),
            |total, packet| total.saturating_add(u64::from(packet.length())),
        )
    }

    fn queue_ingress_deficit(&mut self, at: Duration) {
        if self.ingress_deficit == 0 {
            return;
        }
        // Incoming slots represent receive-credit bytes, not shapeable UDP
        // payloads.  Even a sub-MIN_SHAPED_PAYLOAD residual is therefore an
        // exact, standards-compliant MAX_STREAM_DATA increase.
        let bytes = u16::try_from(
            self.ingress_deficit
                .min(u64::from(self.ingress_packet_size)),
        )
        .unwrap_or(self.ingress_packet_size);
        let Ok(packet) = Packet::new(at, Direction::Incoming, bytes) else {
            // The residual cannot be represented at this timestamp. Account
            // for it now instead of leaving invisible, non-terminating debt.
            self.ingress_shortfall = self.ingress_shortfall.saturating_add(self.ingress_deficit);
            self.ingress_deficit = 0;
            return;
        };
        self.ingress_deficit = self.ingress_deficit.saturating_sub(u64::from(bytes));
        self.pending.push_back(packet);
    }

    fn resolve_ingress(&mut self, at: Duration, packet: Packet, outcome: EventOutcome) {
        let Some(index) = self
            .awaiting_ingress
            .iter()
            .position(|candidate| *candidate == packet)
        else {
            return;
        };
        let Some(packet) = self.awaiting_ingress.remove(index) else {
            return;
        };
        let desired = u64::from(packet.length());
        if let EventOutcome::Satisfied { observed } = outcome {
            let credited = u64::from(observed).min(desired);
            self.ingress_requested = self.ingress_requested.saturating_add(credited);
            self.ingress_outstanding = self.ingress_outstanding.saturating_add(credited);
            self.ingress_credit_outstanding =
                self.ingress_credit_outstanding.saturating_add(credited);
            let uncredited = desired.saturating_sub(credited);
            self.ingress_shortfall = self.ingress_shortfall.saturating_add(uncredited);
        } else if self.application_complete {
            self.ingress_shortfall = self.ingress_shortfall.saturating_add(desired);
        } else {
            // This is a stage transition for already-admitted debt, so it must
            // not be capped a second time or silently truncated.
            self.ingress_deficit = self.ingress_deficit.saturating_add(desired);
        }
        self.finish_ingress_deficit(at);
        debug_assert!(self.unresolved_ingress_bytes() <= self.max_ingress_deficit_bytes);
    }

    fn observe_ingress_cover(&mut self, bytes: u64) {
        let realized = bytes.min(self.ingress_outstanding);
        self.ingress_outstanding = self.ingress_outstanding.saturating_sub(realized);
        self.ingress_received = self.ingress_received.saturating_add(realized);
    }

    fn consume_ingress_credit(&mut self, bytes: u64) {
        let consumed = bytes.min(self.ingress_credit_outstanding);
        self.ingress_credit_outstanding = self.ingress_credit_outstanding.saturating_sub(consumed);
        self.record_uncovered_ingress();
    }

    fn retire_ingress_credit(&mut self, bytes: u64) {
        let retired = bytes.min(self.ingress_credit_outstanding);
        self.ingress_credit_outstanding = self.ingress_credit_outstanding.saturating_sub(retired);
        self.record_uncovered_ingress();
    }

    const fn record_uncovered_ingress(&mut self) {
        let uncovered = self
            .ingress_outstanding
            .saturating_sub(self.ingress_credit_outstanding);
        self.ingress_outstanding = self.ingress_outstanding.saturating_sub(uncovered);
        self.ingress_shortfall = self.ingress_shortfall.saturating_add(uncovered);
    }

    fn record_egress(&mut self, source: u16, outcome: TrafficMorphingOutcome) {
        self.egress_source_bytes = self.egress_source_bytes.saturating_add(u64::from(source));
        match outcome {
            TrafficMorphingOutcome::Morphed { target_udp_size } => {
                self.egress_distribution.observe(target_udp_size);
                self.egress_packets = self.egress_packets.saturating_add(1);
                self.egress_target_bytes = self
                    .egress_target_bytes
                    .saturating_add(u64::from(target_udp_size));
            }
            TrafficMorphingOutcome::Bypassed { reason } => {
                self.egress_distribution.observe(source);
                self.egress_bypasses = self.egress_bypasses.saturating_add(1);
                let counter = match reason {
                    TrafficMorphingBypassReason::PacingLimited => &mut self.egress_pacing_bypasses,
                    TrafficMorphingBypassReason::CongestionLimited => {
                        &mut self.egress_congestion_bypasses
                    }
                    TrafficMorphingBypassReason::Coalesced => &mut self.egress_coalesced_bypasses,
                    TrafficMorphingBypassReason::InvalidPacketSize => {
                        &mut self.egress_invalid_size_bypasses
                    }
                    TrafficMorphingBypassReason::TargetSelectionFailed => {
                        &mut self.egress_target_selection_bypasses
                    }
                };
                *counter = counter.saturating_add(1);
            }
        }
    }

    fn finish_application(&mut self, at: Duration) {
        if self.application_complete {
            return;
        }
        self.application_complete = true;
        self.finish_ingress_deficit(at);
    }

    fn finish_ingress_deficit(&mut self, at: Duration) {
        self.queue_ingress_deficit(at);
    }
}

impl Defense for TrafficMorphing {
    fn observe(&mut self, signal: DefenseSignal) {
        match signal.kind {
            SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length,
                class: QcsdDatagramClass::Natural,
            } => {
                self.ingress_distribution.observe(length);
                self.on_incoming_wire(signal.at, length);
            }
            SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length,
                class: QcsdDatagramClass::DefenseCover,
            } => {
                self.ingress_distribution.observe(length);
                self.suppressed_cover_feedback = self.suppressed_cover_feedback.saturating_add(1);
            }
            SignalKind::TrafficMorphingEgress { source, outcome } => {
                self.record_egress(source, outcome);
            }
            SignalKind::ApplicationComplete => self.finish_application(signal.at),
            SignalKind::Resolved { packet, outcome } => {
                if packet.direction() == Direction::Incoming {
                    self.resolve_ingress(signal.at, packet, outcome);
                }
            }
            SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover: true,
            } => self.observe_ingress_cover(bytes),
            SignalKind::ReceiveCreditRetired { bytes } => self.retire_ingress_credit(bytes),
            SignalKind::ReceiveCreditConsumed { bytes } => self.consume_ingress_credit(bytes),
            SignalKind::Wire { .. }
            | SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                ..
            }
            | SignalKind::PayloadBytes { .. }
            | SignalKind::ApplicationBatchStarted
            | SignalKind::ApplicationBatchCompleted
            | SignalKind::Capacity(_) => {}
        }
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        self.pending
            .front()
            .filter(|packet| packet.timestamp() <= elapsed)?;
        let packet = self.pending.pop_front()?;
        self.awaiting_ingress.push_back(packet);
        Some(packet)
    }

    fn next_event_at(&self) -> Option<Duration> {
        self.pending.front().map(|packet| packet.timestamp())
    }

    fn is_complete(&self) -> bool {
        self.application_complete
            && self.unresolved_ingress_bytes() == 0
            && self.ingress_credit_outstanding == 0
    }

    fn is_outgoing_complete(&self) -> bool {
        true
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffOnly
    }

    fn diagnostics(&self) -> DefenseDiagnostics {
        DefenseDiagnostics {
            morphing_egress_packets: self.egress_packets,
            morphing_egress_source_bytes: self.egress_source_bytes,
            morphing_egress_target_bytes: self.egress_target_bytes,
            morphing_egress_bypasses: self.egress_bypasses,
            morphing_egress_pacing_bypasses: self.egress_pacing_bypasses,
            morphing_egress_congestion_bypasses: self.egress_congestion_bypasses,
            morphing_egress_coalesced_bypasses: self.egress_coalesced_bypasses,
            morphing_egress_invalid_size_bypasses: self.egress_invalid_size_bypasses,
            morphing_egress_target_selection_bypasses: self.egress_target_selection_bypasses,
            morphing_egress_target_l1_ppm: self.egress_distribution.l1_ppm(),
            morphing_ingress_requested_bytes: self.ingress_requested,
            morphing_ingress_received_bytes: self.ingress_received,
            morphing_ingress_shortfall_bytes: self
                .ingress_shortfall
                .saturating_add(self.unresolved_ingress_bytes()),
            morphing_ingress_target_l1_ppm: self.ingress_distribution.l1_ppm(),
            suppressed_cover_feedback: self.suppressed_cover_feedback,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{TrafficMorphing, TrafficMorphingEgress};
    use crate::{
        Defense as _, DefenseSignal, Direction, EventOutcome, MissedSlotReason, QcsdDatagramClass,
        SignalKind, TrafficMorphingBypassReason, TrafficMorphingConfig, TrafficMorphingOutcome,
    };

    fn config() -> TrafficMorphingConfig {
        TrafficMorphingConfig {
            matrix: "test-matrix.json".into(),
            workload_id: "real".into(),
            ingress_packet_size: 200,
            max_ingress_deficit_bytes: 1_000,
        }
    }

    fn matrix() -> String {
        r#"{
            "adaptation": "qcsd-client-only",
            "buckets": [64, 200],
            "generated_by": "test",
            "paper_equivalent": false,
            "profiles": [{
                "incoming": {
                    "expected_added_bytes": 136.0,
                    "l1_distance": 0.0,
                    "realized_distribution": [0.0, 1.0],
                    "rows": [[0.0, 1.0], [0.0, 1.0]],
                    "source_distribution": [1.0, 0.0],
                    "target_distribution": [0.0, 1.0]
                },
                "outgoing": {
                    "expected_added_bytes": 34.0,
                    "l1_distance": 0.0,
                    "realized_distribution": [0.25, 0.75],
                    "rows": [[0.5, 0.5], [0.0, 1.0]],
                    "source_distribution": [0.5, 0.5],
                    "target_distribution": [0.25, 0.75]
                },
                "source": "real",
                "target": "decoy"
            }],
            "schema_version": 2,
            "udp_payload_ceiling": 200
        }"#
        .into()
    }

    #[test]
    fn strict_loader_rejects_downward_mass_and_wrong_ceiling() {
        let downward = matrix().replace(
            r#""rows": [[0.0, 1.0], [0.0, 1.0]]"#,
            r#""rows": [[0.0, 1.0], [0.1, 0.9]]"#,
        );
        assert!(TrafficMorphing::from_json(&config(), 1, 200, &downward).is_err());
        assert!(TrafficMorphing::from_json(&config(), 1, 1_200, &matrix()).is_err());
    }

    #[test]
    fn strict_loader_selects_exactly_one_workload_profile() {
        let missing = TrafficMorphingConfig {
            workload_id: "missing".into(),
            ..config()
        };
        let error = TrafficMorphing::from_json(&missing, 1, 200, &matrix())
            .expect_err("missing workload profile");
        assert!(error.to_string().contains("no profile"));

        let mut duplicate: serde_json::Value =
            serde_json::from_str(&matrix()).expect("test matrix JSON");
        let duplicate_profile = duplicate["profiles"][0].clone();
        duplicate["profiles"]
            .as_array_mut()
            .expect("profiles")
            .push(duplicate_profile);
        let duplicate = serde_json::to_string(&duplicate).expect("serialize duplicate");
        let error = TrafficMorphing::from_json(&config(), 1, 200, &duplicate)
            .expect_err("duplicate workload profile");
        assert!(error.to_string().contains("duplicate source profile"));

        let mut bundle: serde_json::Value =
            serde_json::from_str(&matrix()).expect("test matrix JSON");
        let mut other = bundle["profiles"][0].clone();
        other["source"] = json!("other");
        other["target"] = json!("other-decoy");
        other["outgoing"] = json!({
            "expected_added_bytes": 0.0,
            "l1_distance": 0.0,
            "realized_distribution": [1.0, 0.0],
            "rows": [[1.0, 0.0], [0.0, 1.0]],
            "source_distribution": [1.0, 0.0],
            "target_distribution": [1.0, 0.0]
        });
        bundle["profiles"]
            .as_array_mut()
            .expect("profiles")
            .push(other);
        let selected = TrafficMorphingConfig {
            workload_id: "other".into(),
            ..config()
        };
        let mut egress = TrafficMorphingEgress::from_json(
            &selected,
            1,
            200,
            &serde_json::to_string(&bundle).expect("serialize bundle"),
        )
        .expect("select second profile");
        assert_eq!(egress.sample_target(64), Some(64));
    }

    #[test]
    fn egress_sampler_is_seeded_and_never_shrinks() {
        let mut first =
            TrafficMorphingEgress::from_json(&config(), 7, 200, &matrix()).expect("matrix");
        let mut second =
            TrafficMorphingEgress::from_json(&config(), 7, 200, &matrix()).expect("matrix");
        let first_samples: Vec<_> = std::iter::repeat_with(|| first.sample_target(64))
            .take(32)
            .collect();
        let second_samples: Vec<_> = std::iter::repeat_with(|| second.sample_target(64))
            .take(32)
            .collect();
        assert_eq!(first_samples, second_samples);
        assert!(
            first_samples
                .iter()
                .all(|target| target.is_some_and(|value| value >= 64))
        );
    }

    #[test]
    fn capacity_preflight_is_row_specific_and_does_not_consume_rng() {
        let mut preflight =
            TrafficMorphingEgress::from_json(&config(), 7, 200, &matrix()).expect("matrix");
        let mut untouched =
            TrafficMorphingEgress::from_json(&config(), 7, 200, &matrix()).expect("matrix");

        assert_eq!(preflight.maximum_target_for(64), Some(200));
        assert_eq!(preflight.maximum_safe_source_for(64, 199), None);
        assert_eq!(preflight.maximum_safe_source_for(64, 200), Some(200));
        assert_eq!(preflight.sample_target(64), untouched.sample_target(64));
    }

    #[test]
    fn controller_emits_only_incoming_realization_and_records_egress() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Wire {
                direction: Direction::Outgoing,
                length: 64,
            },
        });
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let event = defense
            .next_event(Duration::from_micros(2))
            .expect("incoming realization");
        assert_eq!(event.direction(), Direction::Incoming);
        assert_eq!(event.length(), 136);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 136,
                cover: true,
            },
        });

        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::TrafficMorphingEgress {
                source: 64,
                outcome: TrafficMorphingOutcome::Morphed {
                    target_udp_size: 200,
                },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(6),
            kind: SignalKind::TrafficMorphingEgress {
                source: 80,
                outcome: TrafficMorphingOutcome::Bypassed {
                    reason: TrafficMorphingBypassReason::Coalesced,
                },
            },
        });
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_egress_packets, 1);
        assert_eq!(diagnostics.morphing_egress_source_bytes, 144);
        assert_eq!(diagnostics.morphing_egress_target_bytes, 200);
        assert_eq!(diagnostics.morphing_egress_bypasses, 1);
        assert_eq!(diagnostics.morphing_egress_coalesced_bypasses, 1);
        assert_eq!(diagnostics.morphing_egress_target_l1_ppm, 500_000);
        assert_eq!(diagnostics.morphing_ingress_requested_bytes, 136);
        assert_eq!(diagnostics.morphing_ingress_received_bytes, 136);
        assert_eq!(diagnostics.morphing_ingress_shortfall_bytes, 0);
        assert_eq!(diagnostics.morphing_ingress_target_l1_ppm, 2_000_000);
    }

    #[test]
    fn subminimum_ingress_deficit_is_exact_receive_credit() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        // This second observation contributes a 32-byte receive-credit event,
        // even though 32 would be too small for an outgoing shaped datagram.
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 168,
                class: QcsdDatagramClass::Natural,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ApplicationComplete,
        });
        let event = defense
            .next_event(Duration::from_micros(3))
            .expect("pending ingress cover");
        assert_eq!(event.length(), 136);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        let residual = defense
            .next_event(Duration::from_micros(4))
            .expect("subminimum receive-credit event");
        assert_eq!(residual.length(), 32);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::Resolved {
                packet: residual,
                outcome: EventOutcome::Satisfied { observed: 32 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(6),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 168,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(6),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 168 },
        });

        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_ingress_requested_bytes, 168);
        assert_eq!(diagnostics.morphing_ingress_received_bytes, 168);
        assert_eq!(diagnostics.morphing_ingress_shortfall_bytes, 0);
    }

    #[test]
    fn total_ingress_guard_bounds_pending_awaiting_and_resolved_debt() {
        let bounded = TrafficMorphingConfig {
            max_ingress_deficit_bytes: 200,
            ..config()
        };
        let mut defense = TrafficMorphing::from_json(&bounded, 9, 200, &matrix()).expect("matrix");

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        assert_eq!(defense.unresolved_ingress_bytes(), 136);
        let first = defense
            .next_event(Duration::from_micros(1))
            .expect("first admitted event");
        assert_eq!(defense.unresolved_ingress_bytes(), 136);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        assert_eq!(defense.unresolved_ingress_bytes(), 200);
        let second = defense
            .next_event(Duration::from_micros(2))
            .expect("guard residual event");
        assert_eq!(second.length(), 64);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::Resolved {
                packet: first,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        assert_eq!(defense.unresolved_ingress_bytes(), 200);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        assert_eq!(defense.unresolved_ingress_bytes(), 200);
        assert_eq!(defense.next_event(Duration::from_micros(4)), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::Resolved {
                packet: second,
                outcome: EventOutcome::Satisfied { observed: 64 },
            },
        });
        let guarded = defense.diagnostics();
        assert_eq!(guarded.morphing_ingress_shortfall_bytes, 408);
        assert_eq!(guarded.morphing_ingress_requested_bytes, 200);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(6),
            kind: SignalKind::ApplicationComplete,
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(7),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 200,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(7),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 200 },
        });

        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_ingress_requested_bytes, 200);
        assert_eq!(diagnostics.morphing_ingress_received_bytes, 200);
        assert_eq!(diagnostics.morphing_ingress_shortfall_bytes, 208);
    }

    #[test]
    fn missed_ingress_is_retried_without_reopening_the_guard() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let first = defense
            .next_event(Duration::from_micros(1))
            .expect("first attempt");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::Resolved {
                packet: first,
                outcome: EventOutcome::Missed(MissedSlotReason::NoEndpoint),
            },
        });
        assert_eq!(defense.unresolved_ingress_bytes(), 136);
        assert_eq!(defense.ingress_shortfall, 0);

        let retry = defense
            .next_event(Duration::from_micros(2))
            .expect("exact retry");
        assert_eq!(retry.length(), 136);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ApplicationComplete,
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::Resolved {
                packet: retry,
                outcome: EventOutcome::Missed(MissedSlotReason::EndpointClosed),
            },
        });

        assert!(defense.is_complete());
        assert_eq!(defense.unresolved_ingress_bytes(), 0);
        assert_eq!(defense.diagnostics().morphing_ingress_shortfall_bytes, 136);
    }

    #[test]
    fn partial_credit_and_retirement_are_explicit_shortfall() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let event = defense
            .next_event(Duration::from_micros(1))
            .expect("incoming realization");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 100 },
            },
        });
        assert_eq!(defense.ingress_shortfall, 36);
        assert_eq!(defense.unresolved_ingress_bytes(), 100);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 60,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 60 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ReceiveCreditRetired { bytes: 40 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_ingress_requested_bytes, 100);
        assert_eq!(diagnostics.morphing_ingress_received_bytes, 60);
        assert_eq!(diagnostics.morphing_ingress_shortfall_bytes, 76);
    }

    #[test]
    fn scheduled_credit_consumed_by_natural_payload_is_not_claimed_as_cover() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let event = defense
            .next_event(Duration::from_micros(1))
            .expect("incoming realization");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 136,
                cover: false,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 136 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_ingress_received_bytes, 0);
        assert_eq!(diagnostics.morphing_ingress_shortfall_bytes, 136);
    }

    #[test]
    fn causally_classified_cover_never_reenters_the_ingress_matrix() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let event = defense
            .next_event(Duration::from_micros(1))
            .expect("natural packet creates one deficit");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 136,
                class: QcsdDatagramClass::DefenseCover,
            },
        });

        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        assert_eq!(defense.diagnostics().suppressed_cover_feedback, 1);
    }

    #[test]
    fn initial_allowance_does_not_consume_morphing_credit_in_flight() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 64,
                class: QcsdDatagramClass::Natural,
            },
        });
        let event = defense
            .next_event(Duration::from_micros(1))
            .expect("incoming realization");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::Resolved {
                packet: event,
                outcome: EventOutcome::Satisfied { observed: 136 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 136,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 120 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(!defense.is_complete());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ReceiveCreditRetired { bytes: 16 },
        });
        assert!(defense.is_complete());
        assert_eq!(defense.diagnostics().morphing_ingress_shortfall_bytes, 0);
    }

    #[test]
    fn distribution_distance_is_integer_deterministic_and_bucketed() {
        let mut defense = TrafficMorphing::from_json(&config(), 9, 200, &matrix()).expect("matrix");
        for target in [64, 200, 200, 200] {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::TrafficMorphingEgress {
                    source: 64,
                    outcome: TrafficMorphingOutcome::Morphed {
                        target_udp_size: target,
                    },
                },
            });
        }
        for length in [64, 200, 200, 200] {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(2),
                kind: SignalKind::ClassifiedWire {
                    direction: Direction::Incoming,
                    length,
                    class: QcsdDatagramClass::Natural,
                },
            });
        }

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.morphing_egress_target_l1_ppm, 0);
        assert_eq!(diagnostics.morphing_ingress_target_l1_ppm, 500_000);
    }
}
