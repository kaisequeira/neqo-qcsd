// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::VecDeque, fs, path::Path, time::Duration};

use serde::Deserialize;

use super::{Defense, DefenseDiagnostics, DefenseMode, DefenseSignal, EventOutcome, SignalKind};
use crate::{
    Direction, Error, Histogram, Packet, QcsdDatagramClass, Result, SplitMix64, WtfPadConfig,
    derive,
};

const SCHEMA_VERSION: u32 = 2;
const ADAPTATION: &str = "qcsd-client-only";
const BANDWIDTH_WINDOW_PACKETS: u8 = 2;
const HISTOGRAM_BIN_COUNT: usize = 20;
const FINITE_HISTOGRAM_BIN_COUNT: usize = HISTOGRAM_BIN_COUNT - 1;
const BURST_INFINITY_FORMULA: &str = "k_inf = p_inf / (1 - p_inf) * K";
const GAP_INFINITY_FORMULA: &str = "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)";
const TUNING_APPLIES_TO: &str = "burst-histogram-only";
const BURST_TUNING_TRANSFORMATION: &str = "paper-gaussian-percentile-shift-v1";
const IDENTITY_TRANSFORMATION: &str = "identity";
const NORMAL_QUANTILE_A: [f64; 6] = [
    -3.969_683_028_665_376e1,
    2.209_460_984_245_205e2,
    -2.759_285_104_469_687e2,
    1.383_577_518_672_69e2,
    -3.066_479_806_614_716e1,
    2.506_628_277_459_239,
];
const NORMAL_QUANTILE_B: [f64; 6] = [
    -5.447_609_879_822_406e1,
    1.615_858_368_580_409e2,
    -1.556_989_798_598_866e2,
    6.680_131_188_771_972e1,
    -1.328_068_155_288_572e1,
    1.0,
];
const NORMAL_QUANTILE_C: [f64; 6] = [
    -7.784_894_002_430_293e-3,
    -3.223_964_580_411_365e-1,
    -2.400_758_277_161_838,
    -2.549_732_539_343_734,
    4.374_664_141_464_968,
    2.938_163_982_698_783,
];
const NORMAL_QUANTILE_D: [f64; 5] = [
    7.784_695_709_041_462e-3,
    3.224_671_290_700_398e-1,
    2.445_134_137_142_996,
    3.754_408_661_907_416,
    1.0,
];
const NORMAL_QUANTILE_LOW: f64 = 0.024_25;
const NORMAL_QUANTILE_HIGH: f64 = 1.0 - NORMAL_QUANTILE_LOW;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistogramFile {
    schema_version: u32,
    adaptation: String,
    paper_equivalent: bool,
    fitted_from: String,
    generated_by: String,
    fitting: FittingRecord,
    outgoing: DirectionHistograms,
    incoming: DirectionHistograms,
}

impl HistogramFile {
    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported WTF-PAD histogram schema version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.adaptation != ADAPTATION || self.paper_equivalent {
            return Err(Error::InvalidConfig(
                "WTF-PAD parameters must declare the qcsd-client-only, non-paper-equivalent adaptation"
                    .into(),
            ));
        }
        if self.fitted_from.trim().is_empty() || self.generated_by.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "WTF-PAD histogram provenance fields must not be empty".into(),
            ));
        }
        self.fitting.validate()?;
        self.outgoing.validate_fitting(&self.fitting)?;
        self.incoming.validate_fitting(&self.fitting)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FittingRecord {
    instantaneous_bandwidth_window_packets: u8,
    burst_threshold_method: String,
    bandwidth_threshold_bytes_per_second: f64,
    candidate_models: Vec<String>,
    tuning_percentile: f64,
    tuning_applies_to: String,
    tuning_transformation: String,
    finite_domain_percentile: f64,
    histogram_bin_count: usize,
    histogram_scale: String,
    finite_token_budget: u32,
    fake_burst_probability: f64,
    infinity_token_formulas: InfinityTokenFormulas,
}

impl FittingRecord {
    fn validate(&self) -> Result<()> {
        if self.instantaneous_bandwidth_window_packets != BANDWIDTH_WINDOW_PACKETS
            || self.burst_threshold_method != "corpus-mean-bandwidth"
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitting must use a two-packet instantaneous-bandwidth window and corpus-mean threshold"
                    .into(),
            ));
        }
        if !self.bandwidth_threshold_bytes_per_second.is_finite()
            || self.bandwidth_threshold_bytes_per_second <= 0.0
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitting bandwidth threshold must be finite and positive".into(),
            ));
        }
        if self.candidate_models != ["normal", "lognormal"] {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitting candidates must be normal and lognormal, in that order".into(),
            ));
        }
        if !self.tuning_percentile.is_finite()
            || !(0.0..=0.5).contains(&self.tuning_percentile)
            || self.tuning_percentile == 0.0
            || self.tuning_applies_to != TUNING_APPLIES_TO
            || self.tuning_transformation != BURST_TUNING_TRANSFORMATION
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD tuning must apply the paper's Gaussian percentile shift only to H_B, with p in (0, 0.5]"
                    .into(),
            ));
        }
        if !self.finite_domain_percentile.is_finite()
            || !(0.0..100.0).contains(&self.finite_domain_percentile)
            || self.finite_domain_percentile == 0.0
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD finite-domain percentile must be strictly between zero and 100".into(),
            ));
        }
        if self.histogram_bin_count != HISTOGRAM_BIN_COUNT
            || self.histogram_scale != "exponential"
            || self.finite_token_budget == 0
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitting must use 20 exponential bins and positive finite-token mass"
                    .into(),
            ));
        }
        if !self.fake_burst_probability.is_finite()
            || !(0.0..1.0).contains(&self.fake_burst_probability)
            || self.fake_burst_probability == 0.0
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD fake-burst probability must be strictly between zero and one".into(),
            ));
        }
        self.infinity_token_formulas.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfinityTokenFormulas {
    burst: String,
    gap: String,
}

impl InfinityTokenFormulas {
    fn validate(&self) -> Result<()> {
        if self.burst != BURST_INFINITY_FORMULA || self.gap != GAP_INFINITY_FORMULA {
            return Err(Error::InvalidConfig(
                "WTF-PAD infinity-token formulas do not match Appendix A".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectionHistograms {
    burst: Histogram,
    gap: Histogram,
    fit: DirectionFit,
}

impl DirectionHistograms {
    fn validate_fitting(&self, fitting: &FittingRecord) -> Result<()> {
        self.burst.validate()?;
        self.gap.validate()?;
        if self.burst.finite_bin_count() != FINITE_HISTOGRAM_BIN_COUNT
            || self.gap.finite_bin_count() != FINITE_HISTOGRAM_BIN_COUNT
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD histograms must contain 19 finite bins plus one infinity bin".into(),
            ));
        }
        self.fit.validate(fitting.tuning_percentile)?;
        let finite_tokens = u64::from(fitting.finite_token_budget);
        for (label, histogram, population) in [
            ("H_B", &self.burst, &self.fit.burst),
            ("H_G", &self.gap, &self.fit.gap),
        ] {
            if histogram.finite_token_count() != finite_tokens {
                return Err(Error::InvalidConfig(format!(
                    "WTF-PAD {label} finite token population does not match its fitting record"
                )));
            }
            if histogram.maximum_finite_edge_us() != Some(population.histogram_max_us) {
                return Err(Error::InvalidConfig(format!(
                    "WTF-PAD {label} histogram maximum does not match its fitted population"
                )));
            }
        }
        let expected_burst_infinity = rounded_positive_tokens(
            ((1.0 - fitting.fake_burst_probability) / fitting.fake_burst_probability)
                * f64::from(fitting.finite_token_budget),
        )?;
        let mean_burst_length = self.fit.mean_burst_length_packets;
        let expected_gap_infinity = rounded_positive_tokens(
            (f64::from(fitting.finite_token_budget) - mean_burst_length + 1.0)
                / (mean_burst_length - 1.0),
        )?;
        if self.burst.infinity_token_count() != expected_burst_infinity
            || self.gap.infinity_token_count() != expected_gap_infinity
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD infinity-token populations do not match the recorded Appendix-A formulas"
                    .into(),
            ));
        }
        Ok(())
    }

    fn into_histograms(self) -> Result<(Histogram, Histogram)> {
        self.burst.validate()?;
        self.gap.validate()?;
        if self.burst.finite_bin_count() != FINITE_HISTOGRAM_BIN_COUNT
            || self.gap.finite_bin_count() != FINITE_HISTOGRAM_BIN_COUNT
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD histograms must contain 19 finite bins plus one infinity bin".into(),
            ));
        }
        Ok((self.burst, self.gap))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectionFit {
    mean_burst_length_packets: f64,
    burst: PopulationFit,
    gap: PopulationFit,
}

impl DirectionFit {
    fn validate(&self, tuning_percentile: f64) -> Result<()> {
        if !self.mean_burst_length_packets.is_finite() || self.mean_burst_length_packets <= 1.0 {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitted mean burst length must exceed one packet".into(),
            ));
        }
        self.burst
            .validate(BURST_TUNING_TRANSFORMATION, Some(tuning_percentile))?;
        self.gap.validate(IDENTITY_TRANSFORMATION, None)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PopulationFit {
    sample_count: usize,
    selected_model: String,
    histogram_max_us: u64,
    runtime_parameters: Vec<f64>,
    parameter_transformation: String,
    candidates: Vec<ModelCandidate>,
}

impl PopulationFit {
    fn validate(
        &self,
        expected_transformation: &str,
        tuning_percentile: Option<f64>,
    ) -> Result<()> {
        if self.sample_count == 0 || self.histogram_max_us == 0 {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitted populations must have samples and a positive maximum".into(),
            ));
        }
        if self.candidates.len() != 2
            || self
                .candidates
                .first()
                .map(|candidate| candidate.name.as_str())
                != Some("normal")
            || self
                .candidates
                .get(1)
                .map(|candidate| candidate.name.as_str())
                != Some("lognormal")
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD population fit must record normal/lognormal candidates and its selection"
                    .into(),
            ));
        }
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        let selected = self
            .candidates
            .iter()
            .find(|candidate| candidate.name == self.selected_model)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "WTF-PAD selected model is absent from the fitted candidates".into(),
                )
            })?;
        if self.parameter_transformation != expected_transformation
            || !valid_model_parameters(&self.selected_model, &self.runtime_parameters)
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD runtime parameters do not match the declared transformation".into(),
            ));
        }
        let expected_parameters = tuning_percentile.map_or_else(
            || Some(selected.parameters.clone()),
            |percentile| tuned_runtime_parameters(selected, percentile),
        );
        if expected_parameters.as_ref().is_none_or(|expected| {
            !approximately_equal_parameters(&self.runtime_parameters, expected)
        }) {
            return Err(Error::InvalidConfig(
                "WTF-PAD runtime parameters do not exactly implement the recorded H_B tuning"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelCandidate {
    name: String,
    parameters: Vec<f64>,
    ks_statistic: f64,
}

impl ModelCandidate {
    fn validate(&self) -> Result<()> {
        if !valid_model_parameters(&self.name, &self.parameters)
            || !self.ks_statistic.is_finite()
            || !(0.0..=1.0).contains(&self.ks_statistic)
        {
            return Err(Error::InvalidConfig(
                "WTF-PAD fitted model parameters or KS statistic are invalid".into(),
            ));
        }
        Ok(())
    }
}

fn valid_model_parameters(name: &str, parameters: &[f64]) -> bool {
    if parameters.iter().any(|value| !value.is_finite()) {
        return false;
    }
    match (name, parameters) {
        ("normal", [_, scale]) => *scale > 0.0,
        ("lognormal", [shape, location, scale]) => *shape > 0.0 && *location == 0.0 && *scale > 0.0,
        _ => false,
    }
}

fn tuned_runtime_parameters(candidate: &ModelCandidate, percentile: f64) -> Option<Vec<f64>> {
    let standard_quantile = inverse_standard_normal(percentile)?;
    let scale_multiplier = (standard_quantile * standard_quantile / 2.0).exp();
    match candidate.name.as_str() {
        "normal" => {
            let [location, scale] = candidate.parameters.as_slice() else {
                return None;
            };
            Some(vec![
                scale.mul_add(standard_quantile, *location),
                scale * scale_multiplier,
            ])
        }
        "lognormal" => {
            let [shape, location, scale] = candidate.parameters.as_slice() else {
                return None;
            };
            if *location != 0.0 {
                return None;
            }
            Some(vec![
                shape * scale_multiplier,
                0.0,
                scale * (shape * standard_quantile).exp(),
            ])
        }
        _ => None,
    }
}

fn approximately_equal_parameters(actual: &[f64], expected: &[f64]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            let tolerance = expected.abs().max(1.0) * 1e-8;
            (actual - expected).abs() <= tolerance
        })
}

fn rounded_positive_tokens(value: f64) -> Result<u32> {
    if !value.is_finite() || value <= 0.0 || value.ceil() > f64::from(u32::MAX) {
        return Err(Error::InvalidConfig(
            "WTF-PAD infinity-token formula produced an invalid population".into(),
        ));
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the preceding finite positive u32 bound makes this conversion safe"
    )]
    let rounded = value.ceil() as u32;
    Ok(rounded)
}

/// Acklam's rational approximation of the standard-normal quantile.
fn inverse_standard_normal(probability: f64) -> Option<f64> {
    if !probability.is_finite() || !(0.0..1.0).contains(&probability) {
        return None;
    }
    let quantile = if probability < NORMAL_QUANTILE_LOW {
        let q = (-2.0 * probability.ln()).sqrt();
        evaluate_polynomial(&NORMAL_QUANTILE_C, q) / evaluate_polynomial(&NORMAL_QUANTILE_D, q)
    } else if probability <= NORMAL_QUANTILE_HIGH {
        let q = probability - 0.5;
        let r = q * q;
        evaluate_polynomial(&NORMAL_QUANTILE_A, r) * q / evaluate_polynomial(&NORMAL_QUANTILE_B, r)
    } else {
        let q = (-2.0 * (1.0 - probability).ln()).sqrt();
        -evaluate_polynomial(&NORMAL_QUANTILE_C, q) / evaluate_polynomial(&NORMAL_QUANTILE_D, q)
    };
    quantile.is_finite().then_some(quantile)
}

fn evaluate_polynomial(coefficients: &[f64], value: f64) -> f64 {
    coefficients.iter().fold(0.0, |result, coefficient| {
        result.mul_add(value, *coefficient)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArmedTimer {
    started_at: Duration,
    deadline: Duration,
    token: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PadState {
    /// No timer is armed. Real traffic restarts the automaton.
    Silent,
    /// A timer selected from `H_B` is armed.
    Burst(ArmedTimer),
    /// A timer selected from `H_G` is armed.
    Gap(ArmedTimer),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StateTransitions {
    silent_to_burst: u64,
    burst_to_gap: u64,
    gap_to_burst: u64,
    burst_to_silent: u64,
}

#[derive(Debug)]
struct DirectionState {
    burst: Histogram,
    gap: Histogram,
    state: PadState,
    transitions: StateTransitions,
}

impl DirectionState {
    const fn new(burst: Histogram, gap: Histogram) -> Self {
        Self {
            burst,
            gap,
            state: PadState::Silent,
            transitions: StateTransitions {
                silent_to_burst: 0,
                burst_to_gap: 0,
                gap_to_burst: 0,
                burst_to_silent: 0,
            },
        }
    }

    const fn deadline(&self) -> Option<Duration> {
        match self.state {
            PadState::Burst(armed) | PadState::Gap(armed) => Some(armed.deadline),
            PadState::Silent => None,
        }
    }

    const fn is_silent(&self) -> bool {
        matches!(self.state, PadState::Silent)
    }

    const fn silence(&mut self) {
        self.state = PadState::Silent;
    }

    fn arm_burst(&mut self, at: Duration, rng: &mut SplitMix64) {
        let Some(sample) = self.burst.sample_armed(rng) else {
            self.transitions.burst_to_silent = self.transitions.burst_to_silent.saturating_add(1);
            self.state = PadState::Silent;
            return;
        };
        let (delay, token) = sample;
        let Some(delay) = delay else {
            self.transitions.burst_to_silent = self.transitions.burst_to_silent.saturating_add(1);
            self.state = PadState::Silent;
            return;
        };
        self.state = PadState::Burst(ArmedTimer {
            started_at: at,
            deadline: at.saturating_add(delay),
            token,
        });
    }

    fn arm_gap(&mut self, at: Duration, rng: &mut SplitMix64) {
        let Some(sample) = self.gap.sample_armed(rng) else {
            self.transitions.gap_to_burst = self.transitions.gap_to_burst.saturating_add(1);
            self.arm_burst(at, rng);
            return;
        };
        let (delay, token) = sample;
        if let Some(delay) = delay {
            self.state = PadState::Gap(ArmedTimer {
                started_at: at,
                deadline: at.saturating_add(delay),
                token,
            });
        } else {
            self.transitions.gap_to_burst = self.transitions.gap_to_burst.saturating_add(1);
            self.arm_burst(at, rng);
        }
    }

    fn fire_timer(&mut self, deadline: Duration, rng: &mut SplitMix64) {
        match self.state {
            PadState::Burst(armed) if armed.deadline == deadline => {
                // The selected H_B token remains consumed because its timer
                // produced padding. A burst timeout starts a synthetic gap.
                self.transitions.burst_to_gap = self.transitions.burst_to_gap.saturating_add(1);
                self.arm_gap(deadline, rng);
            }
            PadState::Gap(armed) if armed.deadline == deadline => {
                // A gap timeout emits another padding packet and stays in G.
                self.arm_gap(deadline, rng);
            }
            PadState::Silent | PadState::Burst(_) | PadState::Gap(_) => {}
        }
    }

    fn on_real(&mut self, at: Duration, rng: &mut SplitMix64) {
        match self.state {
            PadState::Silent => {
                self.transitions.silent_to_burst =
                    self.transitions.silent_to_burst.saturating_add(1);
                self.arm_burst(at, rng);
            }
            PadState::Burst(armed) => {
                // The real packet won the race with the H_B timer. Undo the
                // sampled token, account the actual inter-arrival using the
                // paper's next-greater-bin rule, and remain in B.
                self.burst.restore_token(armed.token);
                self.burst.remove_token(at.saturating_sub(armed.started_at));
                self.arm_burst(at, rng);
            }
            PadState::Gap(armed) => {
                // Real traffic ends the synthetic gap and returns to B after
                // correcting H_G for the observed inter-arrival.
                self.gap.restore_token(armed.token);
                self.gap.remove_token(at.saturating_sub(armed.started_at));
                self.transitions.gap_to_burst = self.transitions.gap_to_burst.saturating_add(1);
                self.arm_burst(at, rng);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IncomingRealizationState {
    Desired,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IncomingRealization {
    packet: Packet,
    remaining_bytes: u64,
    state: IncomingRealizationState,
    /// Largest part of one timestamped HTTP/3 `BytesRead` aggregate causally
    /// attributed to this desired event.
    representative_bytes: u64,
    /// Timestamp of `representative_bytes`; the first observation wins ties.
    representative_at: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IncomingEventKind {
    Desired,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingEvent {
    packet: Packet,
    incoming_kind: Option<IncomingEventKind>,
}

impl PendingEvent {
    const fn desired(packet: Packet) -> Self {
        Self {
            packet,
            incoming_kind: match packet.direction() {
                Direction::Incoming => Some(IncomingEventKind::Desired),
                Direction::Outgoing => None,
            },
        }
    }

    const fn retry(packet: Packet) -> Self {
        Self {
            packet,
            incoming_kind: Some(IncomingEventKind::Retry),
        }
    }
}

/// WTF-PAD adaptive-padding chaff-only defense.
#[derive(Debug)]
pub struct WtfPad {
    incoming: DirectionState,
    outgoing: DirectionState,
    rng: SplitMix64,
    packet_size: u16,
    max_padding_events: u64,
    padding_events: u64,
    event_guard_triggered: bool,
    pending: VecDeque<PendingEvent>,
    awaiting_incoming: VecDeque<PendingEvent>,
    incoming_realizations: VecDeque<IncomingRealization>,
    incoming_credit_outstanding: u64,
    incoming_desired_bytes: u64,
    incoming_requested_bytes: u64,
    incoming_received_bytes: u64,
    incoming_size_error_bytes: u64,
    incoming_observed_events: u64,
    incoming_lag_us_total: u64,
    incoming_lag_us_max: u64,
    suppressed_cover_feedback: u64,
    application_complete: bool,
}

impl WtfPad {
    /// Load version-two adaptive-padding histograms from `config.histograms`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, JSON envelope, or any
    /// histogram is invalid.
    pub fn new(config: &WtfPadConfig, seed: u64, max_udp_payload_size: u16) -> Result<Self> {
        Self::from_file(config, seed, max_udp_payload_size, &config.histograms)
    }

    /// Load version-two adaptive-padding histograms from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, JSON envelope, or any
    /// histogram is invalid.
    pub fn from_file<P: AsRef<Path>>(
        config: &WtfPadConfig,
        seed: u64,
        max_udp_payload_size: u16,
        path: P,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let input = fs::read_to_string(path)?;
        Self::from_json(config, seed, max_udp_payload_size, &input)
    }

    /// Parse version-two adaptive-padding histograms.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, unknown fields,
    /// inconsistent histogram data, or unsafe defense limits.
    pub fn from_json(
        config: &WtfPadConfig,
        seed: u64,
        max_udp_payload_size: u16,
        input: &str,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file: HistogramFile = serde_json::from_str(input)?;
        file.validate()?;

        let (outgoing_burst, outgoing_gap) = file.outgoing.into_histograms()?;
        let (incoming_burst, incoming_gap) = file.incoming.into_histograms()?;
        let rng = derive(seed, "wtf-pad");
        // Retain a derived stream even though the paper automaton deliberately
        // starts silent and consumes no randomness before its first real
        // packet.
        let outgoing = DirectionState::new(outgoing_burst, outgoing_gap);
        let incoming = DirectionState::new(incoming_burst, incoming_gap);

        Ok(Self {
            incoming,
            outgoing,
            rng,
            packet_size: config.packet_size,
            max_padding_events: config.max_padding_events,
            padding_events: 0,
            event_guard_triggered: false,
            pending: VecDeque::new(),
            awaiting_incoming: VecDeque::new(),
            incoming_realizations: VecDeque::new(),
            incoming_credit_outstanding: 0,
            incoming_desired_bytes: 0,
            incoming_requested_bytes: 0,
            incoming_received_bytes: 0,
            incoming_size_error_bytes: 0,
            incoming_observed_events: 0,
            incoming_lag_us_total: 0,
            incoming_lag_us_max: 0,
            suppressed_cover_feedback: 0,
            application_complete: false,
        })
    }

    const fn state_mut(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::Outgoing => &mut self.outgoing,
            Direction::Incoming => &mut self.incoming,
        }
    }

    fn next_timer(&self) -> Option<(Duration, Direction)> {
        let outgoing = self
            .outgoing
            .deadline()
            .map(|deadline| (deadline, Direction::Outgoing));
        let incoming = self
            .incoming
            .deadline()
            .map(|deadline| (deadline, Direction::Incoming));
        outgoing
            .into_iter()
            .chain(incoming)
            .min_by_key(|(deadline, direction)| {
                (
                    *deadline,
                    match direction {
                        Direction::Outgoing => 0_u8,
                        Direction::Incoming => 1_u8,
                    },
                )
            })
    }

    fn stop_for_guard(&mut self) {
        self.event_guard_triggered = true;
        self.outgoing.silence();
        self.incoming.silence();
        let unrealized = std::mem::take(&mut self.incoming_realizations);
        for realization in unrealized {
            self.finalize_incoming_realization(&realization);
        }
    }

    fn fire_next_due(&mut self, elapsed: Duration) -> Option<PendingEvent> {
        let (deadline, direction) = self.next_timer()?;
        if deadline > elapsed {
            return None;
        }
        let Ok(packet) = Packet::new(deadline, direction, self.packet_size) else {
            self.state_mut(direction).silence();
            return None;
        };

        match direction {
            Direction::Outgoing => self.outgoing.fire_timer(deadline, &mut self.rng),
            Direction::Incoming => self.incoming.fire_timer(deadline, &mut self.rng),
        }
        self.padding_events = self.padding_events.saturating_add(1);
        if direction == Direction::Incoming {
            self.incoming_desired_bytes = self
                .incoming_desired_bytes
                .saturating_add(u64::from(packet.length()));
            self.incoming_realizations.push_back(IncomingRealization {
                packet,
                remaining_bytes: u64::from(packet.length()),
                state: IncomingRealizationState::Desired,
                representative_bytes: 0,
                representative_at: None,
            });
        }
        if self.padding_events >= self.max_padding_events {
            self.stop_for_guard();
        }
        Some(PendingEvent::desired(packet))
    }

    fn materialize_before(&mut self, instant: Duration) {
        while let Some((deadline, _)) = self.next_timer() {
            if deadline >= instant {
                break;
            }
            let Some(event) = self.fire_next_due(deadline) else {
                break;
            };
            self.pending.push_back(event);
        }
    }

    fn emit(&mut self, event: PendingEvent) -> Packet {
        if event.incoming_kind.is_some() {
            self.awaiting_incoming.push_back(event);
        }
        event.packet
    }

    fn resolve_desired_incoming(&mut self, packet: Packet, outcome: EventOutcome) {
        let Some(index) = self.incoming_realizations.iter().position(|realization| {
            realization.packet == packet && realization.state == IncomingRealizationState::Desired
        }) else {
            return;
        };
        if let EventOutcome::Satisfied { observed } = outcome {
            if let Some(realization) = self.incoming_realizations.get_mut(index) {
                realization.state = IncomingRealizationState::Requested;
                self.incoming_requested_bytes = self
                    .incoming_requested_bytes
                    .saturating_add(u64::from(observed));
                self.incoming_credit_outstanding = self
                    .incoming_credit_outstanding
                    .saturating_add(u64::from(observed));
            }
        } else if let Some(realization) = self.incoming_realizations.remove(index) {
            self.finalize_incoming_realization(&realization);
        }
    }

    fn resolve_retry_incoming(&mut self, packet: Packet, outcome: EventOutcome) {
        match outcome {
            EventOutcome::Satisfied { observed } => {
                self.incoming_requested_bytes = self
                    .incoming_requested_bytes
                    .saturating_add(u64::from(observed));
                self.incoming_credit_outstanding = self
                    .incoming_credit_outstanding
                    .saturating_add(u64::from(observed));
                let unencoded = u64::from(packet.length().saturating_sub(observed));
                self.abandon_incoming_bytes(unencoded);
            }
            EventOutcome::Missed(_) => {
                self.abandon_incoming_bytes(u64::from(packet.length()));
            }
        }
    }

    fn resolve_incoming(&mut self, packet: Packet, outcome: EventOutcome) {
        let Some(index) = self
            .awaiting_incoming
            .iter()
            .position(|event| event.packet == packet)
        else {
            return;
        };
        let Some(event) = self.awaiting_incoming.remove(index) else {
            return;
        };
        match event.incoming_kind {
            Some(IncomingEventKind::Desired) => self.resolve_desired_incoming(packet, outcome),
            Some(IncomingEventKind::Retry) => self.resolve_retry_incoming(packet, outcome),
            None => {}
        }
    }

    fn remaining_incoming_bytes(&self) -> u64 {
        self.incoming_realizations
            .iter()
            .fold(0_u64, |total, realization| {
                total.saturating_add(realization.remaining_bytes)
            })
    }

    fn prospective_incoming_credit(&self) -> u64 {
        let desired = self
            .incoming_realizations
            .iter()
            .filter(|realization| realization.state == IncomingRealizationState::Desired)
            .fold(0_u64, |total, realization| {
                total.saturating_add(realization.remaining_bytes)
            });
        let retries = self
            .pending
            .iter()
            .chain(self.awaiting_incoming.iter())
            .filter(|event| event.incoming_kind == Some(IncomingEventKind::Retry))
            .fold(0_u64, |total, event| {
                total.saturating_add(u64::from(event.packet.length()))
            });
        desired.saturating_add(retries)
    }

    fn queue_retry(&mut self, at: Duration, bytes: u64) {
        let mut remaining = bytes;
        while remaining > 0 {
            let length = u16::try_from(remaining.min(u64::from(self.packet_size)))
                .unwrap_or(self.packet_size);
            let Ok(packet) = Packet::new(at, Direction::Incoming, length) else {
                self.abandon_incoming_bytes(remaining);
                return;
            };
            self.pending.push_back(PendingEvent::retry(packet));
            remaining = remaining.saturating_sub(u64::from(length));
        }
    }

    const fn receive_credit_consumed(&mut self, bytes: u64) {
        self.incoming_credit_outstanding = self.incoming_credit_outstanding.saturating_sub(bytes);
    }

    fn receive_credit_retired(&mut self, at: Duration, bytes: u64) {
        let retired = bytes.min(self.incoming_credit_outstanding);
        self.incoming_credit_outstanding = self.incoming_credit_outstanding.saturating_sub(retired);
        let covered = self
            .incoming_credit_outstanding
            .saturating_add(self.prospective_incoming_credit());
        let uncovered = self.remaining_incoming_bytes().saturating_sub(covered);
        self.queue_retry(at, retired.min(uncovered));
    }

    fn abandon_incoming_bytes(&mut self, mut bytes: u64) {
        let mut outstanding = VecDeque::with_capacity(self.incoming_realizations.len());
        let mut completed = Vec::new();
        while let Some(mut realization) = self.incoming_realizations.pop_front() {
            if bytes == 0 {
                outstanding.push_back(realization);
                outstanding.append(&mut self.incoming_realizations);
                break;
            }
            if realization.state != IncomingRealizationState::Requested {
                outstanding.push_back(realization);
                continue;
            }
            let abandoned = bytes.min(realization.remaining_bytes);
            realization.remaining_bytes = realization.remaining_bytes.saturating_sub(abandoned);
            bytes = bytes.saturating_sub(abandoned);
            if realization.remaining_bytes == 0 {
                completed.push(realization);
            } else {
                outstanding.push_back(realization);
            }
        }
        self.incoming_realizations = outstanding;
        for realization in completed {
            self.finalize_incoming_realization(&realization);
        }
    }

    fn realization_metrics(realization: &IncomingRealization) -> (u64, u64, u64) {
        let size_error =
            u64::from(realization.packet.length()).saturating_sub(realization.representative_bytes);
        let Some(observed_at) = realization.representative_at else {
            return (size_error, 0, 0);
        };
        let lag_us = u64::try_from(
            observed_at
                .saturating_sub(realization.packet.timestamp())
                .as_micros(),
        )
        .unwrap_or(u64::MAX);
        (size_error, 1, lag_us)
    }

    fn finalize_incoming_realization(&mut self, realization: &IncomingRealization) {
        let (size_error, observed_events, lag_us) = Self::realization_metrics(realization);
        self.incoming_size_error_bytes = self.incoming_size_error_bytes.saturating_add(size_error);
        self.incoming_observed_events = self
            .incoming_observed_events
            .saturating_add(observed_events);
        self.incoming_lag_us_total = self.incoming_lag_us_total.saturating_add(lag_us);
        if observed_events > 0 {
            self.incoming_lag_us_max = self.incoming_lag_us_max.max(lag_us);
        }
    }

    fn current_incoming_realization_metrics(&self) -> (u64, u64, u64, u64) {
        self.incoming_realizations.iter().fold(
            (
                self.incoming_size_error_bytes,
                self.incoming_observed_events,
                self.incoming_lag_us_total,
                self.incoming_lag_us_max,
            ),
            |(size_error, events, lag_total, lag_max), realization| {
                let (realization_error, realization_events, realization_lag) =
                    Self::realization_metrics(realization);
                (
                    size_error.saturating_add(realization_error),
                    events.saturating_add(realization_events),
                    lag_total.saturating_add(realization_lag),
                    if realization_events > 0 {
                        lag_max.max(realization_lag)
                    } else {
                        lag_max
                    },
                )
            },
        )
    }

    fn observe_incoming_payload(&mut self, at: Duration, mut bytes: u64) {
        // `PayloadBytes` is one HTTP/3 read aggregate. Preserve byte-exact
        // FIFO repayment, but do not merge several aggregates into a
        // fictitious exact-sized observed event. The largest single
        // contribution is the event's deterministic fragmentation proxy.
        let mut outstanding = VecDeque::with_capacity(self.incoming_realizations.len());
        let mut completed = Vec::new();
        while let Some(mut realization) = self.incoming_realizations.pop_front() {
            if bytes == 0 {
                outstanding.push_back(realization);
                outstanding.append(&mut self.incoming_realizations);
                break;
            }
            if realization.state != IncomingRealizationState::Requested {
                outstanding.push_back(realization);
                continue;
            }
            let consumed = bytes.min(realization.remaining_bytes);
            realization.remaining_bytes = realization.remaining_bytes.saturating_sub(consumed);
            bytes = bytes.saturating_sub(consumed);
            self.incoming_received_bytes = self.incoming_received_bytes.saturating_add(consumed);
            if consumed > realization.representative_bytes {
                realization.representative_bytes = consumed;
                realization.representative_at = Some(at);
            }
            if realization.remaining_bytes == 0 {
                completed.push(realization);
            } else {
                outstanding.push_back(realization);
            }
        }
        self.incoming_realizations = outstanding;
        for realization in completed {
            self.finalize_incoming_realization(&realization);
        }
    }
}

impl Defense for WtfPad {
    fn observe(&mut self, signal: DefenseSignal) {
        // Preserve timer decisions whose deadlines have already passed before
        // allowing a later observation to cancel and re-arm that direction.
        // At an exact tie, the trait contract delivers the signal first, so the
        // observation cancels the old timer.
        self.materialize_before(signal.at);

        match signal.kind {
            SignalKind::ClassifiedWire {
                direction,
                class: QcsdDatagramClass::Natural,
                ..
            } => {
                if !self.event_guard_triggered {
                    match direction {
                        Direction::Outgoing => {
                            self.outgoing.on_real(signal.at, &mut self.rng);
                        }
                        Direction::Incoming => {
                            self.incoming.on_real(signal.at, &mut self.rng);
                        }
                    }
                }
            }
            SignalKind::ClassifiedWire {
                class: QcsdDatagramClass::DefenseCover,
                ..
            } => {
                self.suppressed_cover_feedback = self.suppressed_cover_feedback.saturating_add(1);
            }
            SignalKind::ApplicationComplete => self.application_complete = true,
            SignalKind::Resolved { packet, outcome } => {
                if packet.direction() == Direction::Incoming {
                    self.resolve_incoming(packet, outcome);
                }
            }
            SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover: true,
            } => self.observe_incoming_payload(signal.at, bytes),
            SignalKind::ReceiveCreditConsumed { bytes } => {
                self.receive_credit_consumed(bytes);
            }
            SignalKind::ReceiveCreditRetired { bytes } => {
                self.receive_credit_retired(signal.at, bytes);
            }
            SignalKind::Wire { .. }
            | SignalKind::PayloadBytes {
                direction: Direction::Outgoing | Direction::Incoming,
                ..
            }
            | SignalKind::Capacity(_)
            | SignalKind::ApplicationBatchStarted
            | SignalKind::ApplicationBatchCompleted
            | SignalKind::TrafficMorphingEgress { .. } => {}
        }
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        if self
            .pending
            .front()
            .is_some_and(|event| event.packet.timestamp() <= elapsed)
        {
            let event = self.pending.pop_front()?;
            return Some(self.emit(event));
        }
        let event = self.fire_next_due(elapsed)?;
        Some(self.emit(event))
    }

    fn next_event_at(&self) -> Option<Duration> {
        self.pending
            .front()
            .map(|event| event.packet.timestamp())
            .or_else(|| self.next_timer().map(|(deadline, _)| deadline))
    }

    fn is_complete(&self) -> bool {
        self.application_complete
            && self.incoming.is_silent()
            && self.outgoing.is_silent()
            && self.incoming_realizations.is_empty()
            && self.incoming_credit_outstanding == 0
            && self.awaiting_incoming.is_empty()
            && self.pending.is_empty()
    }

    fn is_outgoing_complete(&self) -> bool {
        self.outgoing.is_silent()
            && !self
                .pending
                .iter()
                .any(|event| event.packet.direction() == Direction::Outgoing)
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffOnly
    }

    fn diagnostics(&self) -> DefenseDiagnostics {
        let incoming_shortfall_bytes = self
            .incoming_desired_bytes
            .saturating_sub(self.incoming_received_bytes);
        let (
            incoming_size_error_bytes,
            incoming_observed_events,
            incoming_lag_us_total,
            incoming_lag_us_max,
        ) = self.current_incoming_realization_metrics();
        let transitions = StateTransitions {
            silent_to_burst: self
                .outgoing
                .transitions
                .silent_to_burst
                .saturating_add(self.incoming.transitions.silent_to_burst),
            burst_to_gap: self
                .outgoing
                .transitions
                .burst_to_gap
                .saturating_add(self.incoming.transitions.burst_to_gap),
            gap_to_burst: self
                .outgoing
                .transitions
                .gap_to_burst
                .saturating_add(self.incoming.transitions.gap_to_burst),
            burst_to_silent: self
                .outgoing
                .transitions
                .burst_to_silent
                .saturating_add(self.incoming.transitions.burst_to_silent),
        };
        DefenseDiagnostics {
            padding_events: self.padding_events,
            padding_event_guard_triggered: self.event_guard_triggered,
            wtf_pad_incoming_desired_bytes: self.incoming_desired_bytes,
            wtf_pad_incoming_requested_bytes: self.incoming_requested_bytes,
            wtf_pad_incoming_received_bytes: self.incoming_received_bytes,
            wtf_pad_incoming_shortfall_bytes: incoming_shortfall_bytes,
            wtf_pad_incoming_size_error_bytes: incoming_size_error_bytes,
            wtf_pad_incoming_observed_events: incoming_observed_events,
            wtf_pad_incoming_lag_us_total: incoming_lag_us_total,
            wtf_pad_incoming_lag_us_max: incoming_lag_us_max,
            wtf_pad_silent_to_burst: transitions.silent_to_burst,
            wtf_pad_burst_to_gap: transitions.burst_to_gap,
            wtf_pad_gap_to_burst: transitions.gap_to_burst,
            wtf_pad_burst_to_silent: transitions.burst_to_silent,
            suppressed_cover_feedback: self.suppressed_cover_feedback,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{
        ArmedTimer, BURST_INFINITY_FORMULA, BURST_TUNING_TRANSFORMATION, DirectionState,
        FINITE_HISTOGRAM_BIN_COUNT, GAP_INFINITY_FORMULA, IDENTITY_TRANSFORMATION,
        IncomingRealization, IncomingRealizationState, PadState, StateTransitions,
        TUNING_APPLIES_TO, WtfPad,
    };
    use crate::{
        Defense as _, DefenseMode, DefenseSignal, Direction, EventOutcome, Histogram, Packet,
        QcsdDatagramClass, SignalKind, SplitMix64, WtfPadConfig, defense::drive,
    };

    const MANY_TOKENS: u32 = 10_000;

    fn config(max_padding_events: u64) -> WtfPadConfig {
        WtfPadConfig {
            histograms: "test-histograms.json".into(),
            packet_size: 100,
            max_padding_events,
        }
    }

    fn one_requested_incoming() -> (WtfPad, Packet) {
        let mut defense =
            WtfPad::from_json(&config(10), 17, 1_200, &histograms(10, 10)).expect("histograms");
        defense.incoming.state = PadState::Burst(ArmedTimer {
            started_at: Duration::ZERO,
            deadline: Duration::ZERO,
            token: 0,
        });
        let desired = defense.next_event(Duration::ZERO).expect("desired event");
        defense.incoming.silence();
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Resolved {
                packet: desired,
                outcome: EventOutcome::Satisfied { observed: 100 },
            },
        });
        (defense, desired)
    }

    fn histograms(burst_edge: u64, gap_edge: u64) -> String {
        let edges = |first: u64| {
            (0_u64..FINITE_HISTOGRAM_BIN_COUNT as u64)
                .map(|offset| first.saturating_add(offset).to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let tokens = std::iter::once(MANY_TOKENS.to_string())
            .chain(std::iter::repeat_n(
                "0".to_string(),
                FINITE_HISTOGRAM_BIN_COUNT.saturating_sub(1),
            ))
            .collect::<Vec<_>>()
            .join(",");
        let fit = |maximum: u64, transformation: &str| {
            format!(
                r#"{{
                    "sample_count": 2,
                    "selected_model": "normal",
                    "histogram_max_us": {maximum},
                    "runtime_parameters": [1.0, 1.0],
                    "parameter_transformation": "{transformation}",
                    "candidates": [
                        {{"name": "normal", "parameters": [1.0, 1.0], "ks_statistic": 0.1}},
                        {{"name": "lognormal", "parameters": [1.0, 0.0, 1.0], "ks_statistic": 0.2}}
                    ]
                }}"#
            )
        };
        let burst_edges = edges(burst_edge);
        let gap_edges = edges(gap_edge);
        let burst_fit = fit(
            burst_edge.saturating_add(FINITE_HISTOGRAM_BIN_COUNT as u64 - 1),
            BURST_TUNING_TRANSFORMATION,
        );
        let gap_fit = fit(
            gap_edge.saturating_add(FINITE_HISTOGRAM_BIN_COUNT as u64 - 1),
            IDENTITY_TRANSFORMATION,
        );
        format!(
            r#"{{
                "schema_version": 2,
                "adaptation": "qcsd-client-only",
                "paper_equivalent": false,
                "fitted_from": "test trace",
                "generated_by": "test",
                "fitting": {{
                    "instantaneous_bandwidth_window_packets": 2,
                    "burst_threshold_method": "corpus-mean-bandwidth",
                    "bandwidth_threshold_bytes_per_second": 1.0,
                    "candidate_models": ["normal", "lognormal"],
                    "tuning_percentile": 0.5,
                    "tuning_applies_to": "{TUNING_APPLIES_TO}",
                    "tuning_transformation": "{BURST_TUNING_TRANSFORMATION}",
                    "finite_domain_percentile": 99.5,
                    "histogram_bin_count": 20,
                    "histogram_scale": "exponential",
                    "finite_token_budget": {MANY_TOKENS},
                    "fake_burst_probability": 0.99991,
                    "infinity_token_formulas": {{
                        "burst": "{BURST_INFINITY_FORMULA}",
                        "gap": "{GAP_INFINITY_FORMULA}"
                    }}
                }},
                "outgoing": {{
                    "burst": {{
                        "edges_us": [{burst_edges}],
                        "tokens": [{tokens}],
                        "infinity_tokens": 1
                    }},
                    "gap": {{
                        "edges_us": [{gap_edges}],
                        "tokens": [{tokens}],
                        "infinity_tokens": 1
                    }},
                    "fit": {{
                        "mean_burst_length_packets": 5001.0,
                        "burst": {burst_fit},
                        "gap": {gap_fit}
                    }}
                }},
                "incoming": {{
                    "burst": {{
                        "edges_us": [{burst_edges}],
                        "tokens": [{tokens}],
                        "infinity_tokens": 1
                    }},
                    "gap": {{
                        "edges_us": [{gap_edges}],
                        "tokens": [{tokens}],
                        "infinity_tokens": 1
                    }},
                    "fit": {{
                        "mean_burst_length_packets": 5001.0,
                        "burst": {burst_fit},
                        "gap": {gap_fit}
                    }}
                }}
            }}"#
        )
    }

    fn finite_histograms() -> &'static str {
        include_str!("../../tests/data/wtf-pad-golden.json")
    }

    #[test]
    fn loader_is_strict_at_the_envelope_and_histogram_levels() {
        let envelope_unknown = histograms(10, 5).replace(
            r#""schema_version": 2,"#,
            r#""schema_version": 2, "unexpected": 1,"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &envelope_unknown).is_err());

        let histogram_unknown = histograms(10, 5).replace(
            r#""infinity_tokens": 1"#,
            r#""infinity_tokens": 1, "unexpected": 1"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &histogram_unknown).is_err());

        let wrong_version =
            histograms(10, 5).replace(r#""schema_version": 2"#, r#""schema_version": 1"#);
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_version).is_err());

        let wrong_adaptation = histograms(10, 5).replace("qcsd-client-only", "cooperating-peer");
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_adaptation).is_err());

        let paper_equivalent = histograms(10, 5).replace(
            r#""paper_equivalent": false"#,
            r#""paper_equivalent": true"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &paper_equivalent).is_err());

        let wrong_window = histograms(10, 5).replace(
            r#""instantaneous_bandwidth_window_packets": 2"#,
            r#""instantaneous_bandwidth_window_packets": 3"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_window).is_err());

        let wrong_bin_count = histograms(10, 5).replace(
            r#""histogram_bin_count": 20"#,
            r#""histogram_bin_count": 19"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_bin_count).is_err());

        let out_of_range_tuning =
            histograms(10, 5).replace(r#""tuning_percentile": 0.5"#, r#""tuning_percentile": 0.6"#);
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &out_of_range_tuning).is_err());

        let unshifted_low_percentile =
            histograms(10, 5).replace(r#""tuning_percentile": 0.5"#, r#""tuning_percentile": 0.4"#);
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &unshifted_low_percentile).is_err());

        let shifted_low_percentile = unshifted_low_percentile.replace(
            r#""runtime_parameters": [1.0, 1.0],
                    "parameter_transformation": "paper-gaussian-percentile-shift-v1""#,
            r#""runtime_parameters": [0.7466528968642003, 1.032612890924873],
                    "parameter_transformation": "paper-gaussian-percentile-shift-v1""#,
        );
        WtfPad::from_json(&config(10), 1, 1_200, &shifted_low_percentile)
            .expect("valid lower-percentile H_B shift");

        let shifted_gap = histograms(10, 5).replace(
            r#""parameter_transformation": "identity""#,
            r#""parameter_transformation": "paper-gaussian-percentile-shift-v1""#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &shifted_gap).is_err());

        let wrong_finite_budget = histograms(10, 5).replace(
            r#""finite_token_budget": 10000"#,
            r#""finite_token_budget": 9999"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_finite_budget).is_err());

        let wrong_infinity_formula = histograms(10, 5).replace(
            r#""fake_burst_probability": 0.99991"#,
            r#""fake_burst_probability": 0.9"#,
        );
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_infinity_formula).is_err());

        let wrong_histogram_maximum =
            histograms(10, 5).replace(r#""histogram_max_us": 28"#, r#""histogram_max_us": 29"#);
        assert!(WtfPad::from_json(&config(10), 1, 1_200, &wrong_histogram_maximum).is_err());
    }

    #[test]
    fn automata_do_not_arm_before_the_first_real_packet() {
        let mut defense =
            WtfPad::from_json(&config(10), 7, 1_200, &histograms(0, 1_000)).expect("histograms");

        assert_eq!(defense.next_event_at(), None);
        assert_eq!(defense.next_event(Duration::MAX), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });
        assert!(defense.next_event_at().is_some());
    }

    #[test]
    fn real_activity_cancels_and_rearms_the_burst_histogram() {
        let mut defense =
            WtfPad::from_json(&config(10), 9, 1_200, &histograms(1_000, 10)).expect("histograms");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });

        let deadline = defense.next_event_at().expect("a live timer");
        assert!(matches!(defense.outgoing.state, PadState::Burst(_)));
        assert!(deadline <= Duration::from_micros(1_005));
    }

    #[test]
    fn real_activity_in_gap_corrects_gap_then_arms_burst() {
        let histogram = || {
            serde_json::from_value::<Histogram>(json!({
                "edges_us": [10],
                "tokens": [10],
                "infinity_tokens": 1
            }))
            .expect("histogram")
        };
        let mut burst = histogram();
        let mut gap = histogram();
        burst.refill();
        gap.refill();
        let mut state = DirectionState {
            burst,
            gap,
            state: PadState::Gap(ArmedTimer {
                started_at: Duration::ZERO,
                deadline: Duration::from_secs(1),
                token: 0,
            }),
            transitions: StateTransitions::default(),
        };

        state.on_real(Duration::from_millis(50), &mut SplitMix64::new(7));

        assert_eq!(state.burst.remaining_finite_tokens(), [9]);
        assert!(state.gap.remaining_finite_tokens()[0] < 10);
    }

    #[test]
    fn real_activity_at_the_exact_deadline_cancels_the_old_timer() {
        let mut defense =
            WtfPad::from_json(&config(10), 9, 1_200, &histograms(1_000, 10)).expect("histograms");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });
        let deadline = defense.outgoing.deadline().expect("outgoing idle timer");

        defense.observe(DefenseSignal {
            at: deadline,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });

        assert!(!defense.pending.iter().any(|event| {
            event.packet.direction() == Direction::Outgoing && event.packet.timestamp() == deadline
        }));
    }

    #[test]
    fn emitted_cover_datagram_does_not_rearm_itself_as_real_activity() {
        let mut defense =
            WtfPad::from_json(&config(10), 9, 1_200, &histograms(0, 1_000)).expect("histograms");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });
        let cover = defense.next_event(Duration::ZERO).expect("initial cover");
        let deadline = defense.next_event_at().expect("gap timer");

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Resolved {
                packet: cover,
                outcome: EventOutcome::Satisfied { observed: 100 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 100,
                class: QcsdDatagramClass::DefenseCover,
            },
        });

        assert_eq!(defense.next_event_at(), Some(deadline));
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.suppressed_cover_feedback, 1);
    }

    #[test]
    fn application_completion_does_not_cancel_the_padding_tail() {
        let mut defense =
            WtfPad::from_json(&config(2), 11, 1_200, &histograms(0, 0)).expect("histograms");
        for direction in [Direction::Outgoing, Direction::Incoming] {
            defense.observe(DefenseSignal {
                at: Duration::ZERO,
                kind: SignalKind::ClassifiedWire {
                    direction,
                    length: 80,
                    class: QcsdDatagramClass::Natural,
                },
            });
        }
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });

        assert!(!defense.is_complete());
        assert!(defense.next_event(Duration::ZERO).is_some());
        assert!(defense.next_event(Duration::ZERO).is_some());
        assert_eq!(defense.next_event(Duration::ZERO), None);
        assert!(defense.diagnostics().padding_event_guard_triggered);
        assert_eq!(defense.diagnostics().padding_events, 2);
        assert!(defense.is_complete());
        assert_eq!(defense.mode(), DefenseMode::ChaffOnly);
    }

    #[test]
    fn global_event_guard_stops_both_directions_permanently() {
        let mut defense =
            WtfPad::from_json(&config(1), 13, 1_200, &histograms(0, 0)).expect("histograms");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 80,
                class: QcsdDatagramClass::Natural,
            },
        });

        assert!(defense.next_event(Duration::ZERO).is_some());
        assert_eq!(defense.next_event(Duration::MAX), None);
        assert!(defense.diagnostics().padding_event_guard_triggered);
        assert!(defense.is_outgoing_complete());

        defense.observe(DefenseSignal {
            at: Duration::from_secs(1),
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Outgoing,
                length: 100,
                class: QcsdDatagramClass::Natural,
            },
        });
        assert_eq!(defense.next_event(Duration::MAX), None);
        assert_eq!(defense.diagnostics().padding_events, 1);
    }

    #[test]
    fn infinity_transitions_return_to_silence_and_real_traffic_restarts() {
        let histogram = |finite_tokens, infinity_tokens| {
            serde_json::from_value::<Histogram>(json!({
                "edges_us": [10],
                "tokens": [finite_tokens],
                "infinity_tokens": infinity_tokens
            }))
            .expect("histogram")
        };
        let mut state = DirectionState::new(histogram(1, u32::MAX), histogram(u32::MAX, 1));
        let mut rng = SplitMix64::new(1);

        state.on_real(Duration::ZERO, &mut rng);
        assert_eq!(state.state, PadState::Silent);
        assert_eq!(
            state.transitions,
            StateTransitions {
                silent_to_burst: 1,
                burst_to_silent: 1,
                ..StateTransitions::default()
            }
        );

        state.burst = histogram(u32::MAX, 1);
        state.on_real(Duration::from_micros(20), &mut rng);
        assert!(matches!(state.state, PadState::Burst(_)));
        assert_eq!(state.transitions.silent_to_burst, 2);
    }

    #[test]
    fn gap_infinity_returns_to_burst_instead_of_stopping() {
        let histogram = |finite_tokens, infinity_tokens| {
            serde_json::from_value::<Histogram>(json!({
                "edges_us": [10],
                "tokens": [finite_tokens],
                "infinity_tokens": infinity_tokens
            }))
            .expect("histogram")
        };
        let mut state = DirectionState::new(histogram(u32::MAX, 1), histogram(1, u32::MAX));

        state.arm_gap(Duration::ZERO, &mut SplitMix64::new(1));

        assert!(matches!(state.state, PadState::Burst(_)));
        assert_eq!(state.transitions.gap_to_burst, 1);
        assert_eq!(state.transitions.burst_to_silent, 0);
    }

    #[test]
    fn incoming_credit_does_not_count_as_observed_cover_payload() {
        let mut defense =
            WtfPad::from_json(&config(10), 17, 1_200, &histograms(10, 10)).expect("histograms");
        defense.incoming.state = PadState::Burst(ArmedTimer {
            started_at: Duration::ZERO,
            deadline: Duration::ZERO,
            token: 0,
        });
        let desired = defense.next_event(Duration::ZERO).expect("desired event");
        assert_eq!(desired.direction(), Direction::Incoming);
        defense.incoming.silence();

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Resolved {
                packet: desired,
                outcome: EventOutcome::Satisfied { observed: 100 },
            },
        });
        let requested = defense.diagnostics();
        assert_eq!(requested.wtf_pad_incoming_desired_bytes, 100);
        assert_eq!(requested.wtf_pad_incoming_requested_bytes, 100);
        assert_eq!(requested.wtf_pad_incoming_received_bytes, 0);
        assert_eq!(requested.wtf_pad_incoming_shortfall_bytes, 100);
        assert_eq!(requested.wtf_pad_incoming_size_error_bytes, 100);
        assert_eq!(requested.wtf_pad_incoming_observed_events, 0);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 60,
                cover: true,
            },
        });
        let partial = defense.diagnostics();
        assert_eq!(partial.wtf_pad_incoming_received_bytes, 60);
        assert_eq!(partial.wtf_pad_incoming_shortfall_bytes, 40);
        assert_eq!(partial.wtf_pad_incoming_size_error_bytes, 40);
        assert_eq!(partial.wtf_pad_incoming_observed_events, 1);
        assert_eq!(partial.wtf_pad_incoming_lag_us_total, 4);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(7),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 40,
                cover: true,
            },
        });
        let observed = defense.diagnostics();
        assert_eq!(observed.wtf_pad_incoming_received_bytes, 100);
        assert_eq!(observed.wtf_pad_incoming_shortfall_bytes, 0);
        assert_eq!(observed.wtf_pad_incoming_size_error_bytes, 40);
        assert_eq!(observed.wtf_pad_incoming_observed_events, 1);
        assert_eq!(observed.wtf_pad_incoming_lag_us_total, 4);
        assert_eq!(observed.wtf_pad_incoming_lag_us_max, 4);
    }

    #[test]
    fn initial_allowance_does_not_consume_wtf_pad_credit_in_flight() {
        let (mut defense, _) = one_requested_incoming();
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 100,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 84 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(!defense.is_complete());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ReceiveCreditRetired { bytes: 16 },
        });
        assert!(defense.is_complete());
        assert_eq!(defense.diagnostics().wtf_pad_incoming_shortfall_bytes, 0);
    }

    #[test]
    fn retired_credit_is_retried_and_only_payload_realizes_it() {
        let (mut defense, _) = one_requested_incoming();
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 60,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 60 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRetired { bytes: 40 },
        });
        let retry = defense
            .next_event(Duration::from_micros(3))
            .expect("exact retired-credit retry");
        assert_eq!(retry.length(), 40);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::Resolved {
                packet: retry,
                outcome: EventOutcome::Satisfied { observed: 40 },
            },
        });
        assert_eq!(defense.diagnostics().wtf_pad_incoming_received_bytes, 60);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 40,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 40 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(6),
            kind: SignalKind::ApplicationComplete,
        });

        let diagnostics = defense.diagnostics();
        assert!(defense.is_complete());
        assert_eq!(diagnostics.wtf_pad_incoming_requested_bytes, 140);
        assert_eq!(diagnostics.wtf_pad_incoming_received_bytes, 100);
        assert_eq!(diagnostics.wtf_pad_incoming_shortfall_bytes, 0);
    }

    #[test]
    fn missed_retired_credit_retry_terminates_with_shortfall() {
        let (mut defense, _) = one_requested_incoming();
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 60,
                cover: true,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 60 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRetired { bytes: 40 },
        });
        let retry = defense
            .next_event(Duration::from_micros(3))
            .expect("exact retired-credit retry");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::Resolved {
                packet: retry,
                outcome: EventOutcome::Missed(
                    crate::MissedSlotReason::InsufficientIncomingCapacity,
                ),
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });

        let diagnostics = defense.diagnostics();
        assert!(defense.is_complete());
        assert_eq!(diagnostics.wtf_pad_incoming_received_bytes, 60);
        assert_eq!(diagnostics.wtf_pad_incoming_shortfall_bytes, 40);
    }

    #[test]
    fn fragmented_incoming_cover_has_nonzero_per_event_size_error() {
        let mut large_event = config(10);
        large_event.packet_size = 1_200;
        let mut defense =
            WtfPad::from_json(&large_event, 19, 1_200, &histograms(10, 10)).expect("histograms");
        defense.incoming.state = PadState::Burst(ArmedTimer {
            started_at: Duration::ZERO,
            deadline: Duration::ZERO,
            token: 0,
        });
        let desired = defense.next_event(Duration::ZERO).expect("desired event");
        assert_eq!(desired.length(), 1_200);
        defense.incoming.silence();
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Resolved {
                packet: desired,
                outcome: EventOutcome::Satisfied { observed: 1_200 },
            },
        });

        for at in [Duration::from_micros(4), Duration::from_micros(9)] {
            defense.observe(DefenseSignal {
                at,
                kind: SignalKind::PayloadBytes {
                    direction: Direction::Incoming,
                    bytes: 600,
                    cover: true,
                },
            });
        }

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.wtf_pad_incoming_desired_bytes, 1_200);
        assert_eq!(diagnostics.wtf_pad_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.wtf_pad_incoming_received_bytes, 1_200);
        assert_eq!(diagnostics.wtf_pad_incoming_shortfall_bytes, 0);
        assert_eq!(diagnostics.wtf_pad_incoming_size_error_bytes, 600);
        assert_eq!(diagnostics.wtf_pad_incoming_observed_events, 1);
        assert_eq!(diagnostics.wtf_pad_incoming_lag_us_total, 4);
        assert_eq!(diagnostics.wtf_pad_incoming_lag_us_max, 4);
    }

    #[test]
    fn incoming_aggregate_is_split_fifo_without_erasing_fragmentation() {
        let mut defense =
            WtfPad::from_json(&config(10), 21, 1_200, &histograms(10, 10)).expect("histograms");
        let realizations = [
            Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("first event"),
            Packet::new(Duration::from_micros(5), Direction::Incoming, 100).expect("second event"),
        ];
        defense
            .incoming_realizations
            .extend(realizations.map(|packet| IncomingRealization {
                packet,
                remaining_bytes: 100,
                state: IncomingRealizationState::Requested,
                representative_bytes: 0,
                representative_at: None,
            }));
        defense.incoming_desired_bytes = 200;
        defense.incoming_requested_bytes = 200;

        defense.observe(DefenseSignal {
            at: Duration::from_micros(10),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 150,
                cover: true,
            },
        });
        let partial = defense.diagnostics();
        assert_eq!(partial.wtf_pad_incoming_received_bytes, 150);
        assert_eq!(partial.wtf_pad_incoming_shortfall_bytes, 50);
        assert_eq!(partial.wtf_pad_incoming_size_error_bytes, 50);
        assert_eq!(partial.wtf_pad_incoming_observed_events, 2);
        assert_eq!(partial.wtf_pad_incoming_lag_us_total, 15);
        assert_eq!(partial.wtf_pad_incoming_lag_us_max, 10);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(20),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 50,
                cover: true,
            },
        });
        let complete = defense.diagnostics();
        assert_eq!(complete.wtf_pad_incoming_received_bytes, 200);
        assert_eq!(complete.wtf_pad_incoming_shortfall_bytes, 0);
        assert_eq!(complete.wtf_pad_incoming_size_error_bytes, 50);
        assert_eq!(complete.wtf_pad_incoming_observed_events, 2);
        assert_eq!(complete.wtf_pad_incoming_lag_us_total, 15);
        assert_eq!(complete.wtf_pad_incoming_lag_us_max, 10);
    }

    #[test]
    fn interleaved_real_traffic_drives_both_direction_automata() {
        let mut defense = WtfPad::from_json(&config(10), 23, 1_200, &histograms(1_000, 1_000))
            .expect("histograms");
        for (at, direction) in [
            (1, Direction::Outgoing),
            (2, Direction::Incoming),
            (3, Direction::Outgoing),
            (4, Direction::Incoming),
        ] {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(at),
                kind: SignalKind::ClassifiedWire {
                    direction,
                    length: 80,
                    class: QcsdDatagramClass::Natural,
                },
            });
        }

        assert!(matches!(defense.outgoing.state, PadState::Burst(_)));
        assert!(matches!(defense.incoming.state, PadState::Burst(_)));
        assert_eq!(defense.diagnostics().wtf_pad_silent_to_burst, 2);
    }

    #[test]
    fn pinned_seed_has_a_golden_schedule_and_terminates_without_the_guard() {
        let replay = || {
            let mut defense = WtfPad::from_json(&config(1_000), 0x5eed, 1_200, finite_histograms())
                .expect("histograms");
            let actual = drive(
                &mut defense,
                &[
                    (
                        Duration::ZERO,
                        SignalKind::ClassifiedWire {
                            direction: Direction::Outgoing,
                            length: 80,
                            class: QcsdDatagramClass::Natural,
                        },
                    ),
                    (
                        Duration::from_micros(2),
                        SignalKind::ClassifiedWire {
                            direction: Direction::Incoming,
                            length: 80,
                            class: QcsdDatagramClass::Natural,
                        },
                    ),
                    (Duration::from_millis(1), SignalKind::ApplicationComplete),
                ],
                Duration::from_millis(10),
            )
            .into_iter()
            .map(|packet| (packet.timestamp_us(), packet.direction(), packet.length()))
            .collect::<Vec<_>>();
            assert!(actual.len() < 1_000, "finite fixture must stop naturally");
            assert!(!defense.diagnostics().padding_event_guard_triggered);
            assert_eq!(defense.diagnostics().padding_events, actual.len() as u64);
            assert!(defense.is_complete());
            actual
        };

        let actual = replay();
        assert_eq!(replay(), actual, "an identical signal replay must be exact");
        assert_eq!(
            actual,
            [
                (0, Direction::Outgoing, 100),
                (4, Direction::Outgoing, 100),
                (33, Direction::Outgoing, 100),
                (36, Direction::Outgoing, 100),
                (42, Direction::Outgoing, 100),
                (46, Direction::Outgoing, 100),
            ]
        );
    }
}
