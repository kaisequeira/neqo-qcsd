// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::HashSet, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use super::{
    Defense, DefenseDiagnostics, DefenseMode, DefenseSignal, EventOutcome, SignalKind,
    WalkieTalkieBurstDiagnostics,
};
use crate::{Direction, Error, Packet, Result, WalkieTalkieConfig};

const SCHEMA_VERSION: u32 = 2;
const ADAPTATION: &str = "qcsd-client-only";
const BURST_DEFINITION: &str = "global-application-batch-direction-transitions";
const CELL_BYTE_DOMAIN: &str = "http3-request-stream-offset.bytes";
const MATCHING_ALGORITHM: &str = "minimum-cost-one-to-one";

/// Packet counts in one molded half-duplex burst pair.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BurstPair {
    /// Number of client-to-server shaped packets.
    pub outgoing: u32,
    /// Number of server-to-client receive-credit events.
    pub incoming: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoldedFile {
    adaptation: String,
    burst_definition: String,
    cell_byte_domain: String,
    schema_version: u32,
    generated_by: String,
    matching_algorithm: String,
    paper_equivalent: bool,
    packet_size: u16,
    training_split: String,
    profiles: Vec<MoldedProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoldedProfile {
    real: String,
    decoy: String,
    matching_cost_packets: u64,
    training_inputs: PairTrainingInputs,
    variation: PairVariation,
    source_envelopes: SourceEnvelopes,
    batch_ends: PairBatchEnds,
    molded_batch_ends: Vec<usize>,
    total_scheduled_bytes: u64,
    bursts: Vec<BurstPair>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairTrainingInputs {
    real: Vec<String>,
    decoy: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairVariation {
    real: ProfileVariation,
    decoy: ProfileVariation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileVariation {
    visit_count: usize,
    varying_components: usize,
    maximum_component_spread: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEnvelopes {
    real: Vec<BurstPair>,
    decoy: Vec<BurstPair>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBatchEnds {
    real: Vec<usize>,
    decoy: Vec<usize>,
}

impl MoldedFile {
    fn select_profile(
        &self,
        configured_packet_size: u16,
        workload_id: &str,
    ) -> Result<&MoldedProfile> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported Walkie-Talkie molded-sequence schema version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.adaptation != ADAPTATION
            || self.paper_equivalent
            || self.burst_definition != BURST_DEFINITION
            || self.cell_byte_domain != CELL_BYTE_DOMAIN
            || self.matching_algorithm != MATCHING_ALGORITHM
        {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie parameters must declare the QCSD client-only global-batch \
                 application-STREAM-cell adaptation and minimum-cost one-to-one matching"
                    .into(),
            ));
        }
        if self.generated_by.trim().is_empty() || self.profiles.is_empty() {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie bundle provenance and profiles must not be empty".into(),
            ));
        }
        if !matches!(
            self.training_split.as_str(),
            "train" | "unsealed-engineering" | "reviewed-acceptance-fixture"
        ) {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie training_split is unsupported".into(),
            ));
        }
        if self.packet_size != configured_packet_size {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie molded packet size {} does not match configured packet size {configured_packet_size}",
                self.packet_size
            )));
        }

        let mut identities = HashSet::new();
        let mut selected = None;
        for (index, profile) in self.profiles.iter().enumerate() {
            profile.validate(self.packet_size, index)?;
            for identity in [&profile.real, &profile.decoy] {
                if !identities.insert(identity.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "Walkie-Talkie workload identity {identity:?} occurs in more than one pair"
                    )));
                }
                if identity == workload_id && selected.replace(profile).is_some() {
                    return Err(Error::InvalidConfig(format!(
                        "Walkie-Talkie workload {workload_id:?} matches more than one profile"
                    )));
                }
            }
        }
        selected.ok_or_else(|| {
            Error::InvalidConfig(format!(
                "Walkie-Talkie bundle contains no profile for workload {workload_id:?}"
            ))
        })
    }
}

impl MoldedProfile {
    fn validate(&self, packet_size: u16, profile_index: usize) -> Result<()> {
        if self.real.trim().is_empty() || self.decoy.trim().is_empty() {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie profile {profile_index} workload identities must not be empty"
            )));
        }
        if self.real == self.decoy {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie profile {profile_index} real and decoy labels must be distinct"
            )));
        }
        validate_training_inputs(
            &self.training_inputs.real,
            self.variation.real.visit_count,
            profile_index,
            "real",
        )?;
        validate_training_inputs(
            &self.training_inputs.decoy,
            self.variation.decoy.visit_count,
            profile_index,
            "decoy",
        )?;
        validate_variation(
            &self.variation.real,
            self.source_envelopes.real.len(),
            profile_index,
            "real",
        )?;
        validate_variation(
            &self.variation.decoy,
            self.source_envelopes.decoy.len(),
            profile_index,
            "decoy",
        )?;
        validate_bursts(
            &self.source_envelopes.real,
            profile_index,
            "real source envelope",
        )?;
        validate_bursts(
            &self.source_envelopes.decoy,
            profile_index,
            "decoy source envelope",
        )?;
        validate_bursts(&self.bursts, profile_index, "molded sequence")?;
        validate_batch_ends(
            &self.batch_ends.real,
            self.source_envelopes.real.len(),
            profile_index,
            "real",
        )?;
        validate_batch_ends(
            &self.batch_ends.decoy,
            self.source_envelopes.decoy.len(),
            profile_index,
            "decoy",
        )?;
        validate_batch_ends(
            &self.molded_batch_ends,
            self.bursts.len(),
            profile_index,
            "molded",
        )?;
        validate_derived_mold(self, packet_size, profile_index)
    }
}

fn validate_derived_mold(
    profile: &MoldedProfile,
    packet_size: u16,
    profile_index: usize,
) -> Result<()> {
    let (expected_mold, expected_batch_ends) = mold(
        &profile.source_envelopes.real,
        &profile.batch_ends.real,
        &profile.source_envelopes.decoy,
        &profile.batch_ends.decoy,
    );
    if profile.bursts != expected_mold || profile.molded_batch_ends != expected_batch_ends {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} bursts and common batch boundaries \
             are not the batch-aware element-wise maximum of its source envelopes"
        )));
    }
    let molded_packets = total_packets(&profile.bursts)?;
    let source_packets = total_packets(&profile.source_envelopes.real)?
        .checked_add(total_packets(&profile.source_envelopes.decoy)?)
        .ok_or_else(|| {
            Error::InvalidConfig("Walkie-Talkie source packet count exceeds u64".into())
        })?;
    let expected_cost = molded_packets
        .checked_mul(2)
        .and_then(|value| value.checked_sub(source_packets))
        .ok_or_else(|| Error::InvalidConfig("Walkie-Talkie matching cost exceeds u64".into()))?;
    if profile.matching_cost_packets != expected_cost {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} matching_cost_packets is {}; \
             expected {expected_cost}",
            profile.matching_cost_packets
        )));
    }
    let expected_bytes = molded_packets
        .checked_mul(u64::from(packet_size))
        .ok_or_else(|| {
            Error::InvalidConfig("Walkie-Talkie total scheduled bytes exceeds u64".into())
        })?;
    if profile.total_scheduled_bytes != expected_bytes {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} total_scheduled_bytes is {}; \
             expected {expected_bytes}",
            profile.total_scheduled_bytes
        )));
    }
    Ok(())
}

fn validate_training_inputs(
    inputs: &[String],
    visit_count: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if inputs.is_empty()
        || inputs.len() != visit_count
        || inputs.iter().any(|value| {
            value.len() != 64
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        })
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} training inputs must be lowercase \
             SHA-256 hashes matching variation.visit_count"
        )));
    }
    Ok(())
}

fn validate_variation(
    variation: &ProfileVariation,
    envelope_length: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if variation.visit_count == 0
        || (variation.varying_components == 0) != (variation.maximum_component_spread == 0)
        || variation.varying_components > envelope_length.saturating_mul(2)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} variation is inconsistent"
        )));
    }
    Ok(())
}

fn validate_bursts(bursts: &[BurstPair], profile_index: usize, label: &str) -> Result<()> {
    if bursts.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {label} must not be empty"
        )));
    }
    if let Some(index) = bursts
        .iter()
        .position(|pair| pair.outgoing == 0 && pair.incoming == 0)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {label} burst {index} has no packets"
        )));
    }
    Ok(())
}

fn validate_batch_ends(
    batch_ends: &[usize],
    source_length: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if batch_ends.is_empty()
        || batch_ends.last().copied() != source_length.checked_sub(1)
        || batch_ends
            .iter()
            .zip(batch_ends.iter().skip(1))
            .any(|(left, right)| left >= right)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} batch boundaries must be sorted, \
             unique, in range, and terminate the source envelope"
        )));
    }
    Ok(())
}

fn total_packets(bursts: &[BurstPair]) -> Result<u64> {
    bursts.iter().try_fold(0_u64, |total, pair| {
        total
            .checked_add(u64::from(pair.outgoing) + u64::from(pair.incoming))
            .ok_or_else(|| Error::InvalidConfig("Walkie-Talkie packet count exceeds u64".into()))
    })
}

fn mold(
    real: &[BurstPair],
    real_batch_ends: &[usize],
    decoy: &[BurstPair],
    decoy_batch_ends: &[usize],
) -> (Vec<BurstPair>, Vec<usize>) {
    let real_batches = split_batches(real, real_batch_ends);
    let decoy_batches = split_batches(decoy, decoy_batch_ends);
    let mut molded = Vec::new();
    let mut molded_batch_ends = Vec::new();
    for batch_index in 0..real_batches.len().max(decoy_batches.len()) {
        let real_batch = real_batches.get(batch_index).copied().unwrap_or(&[]);
        let decoy_batch = decoy_batches.get(batch_index).copied().unwrap_or(&[]);
        for component_index in 0..real_batch.len().max(decoy_batch.len()) {
            molded.push(BurstPair {
                outgoing: real_batch
                    .get(component_index)
                    .map_or(0, |pair| pair.outgoing)
                    .max(
                        decoy_batch
                            .get(component_index)
                            .map_or(0, |pair| pair.outgoing),
                    ),
                incoming: real_batch
                    .get(component_index)
                    .map_or(0, |pair| pair.incoming)
                    .max(
                        decoy_batch
                            .get(component_index)
                            .map_or(0, |pair| pair.incoming),
                    ),
            });
        }
        molded_batch_ends.push(molded.len() - 1);
    }
    (molded, molded_batch_ends)
}

fn split_batches<'a>(bursts: &'a [BurstPair], batch_ends: &[usize]) -> Vec<&'a [BurstPair]> {
    let mut start = 0;
    batch_ends
        .iter()
        .map(|end| {
            let batch = &bursts[start..=*end];
            start = end + 1;
            batch
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Turn {
    Outgoing {
        index: usize,
        to_emit: u32,
        awaiting: u32,
    },
    Incoming {
        index: usize,
        credits_to_emit: u32,
        initial_credits_awaiting: u32,
        retry_bytes_to_emit: u64,
        retry_credits_awaiting: u32,
        credited_bytes_outstanding: u64,
        observed_remaining_bytes: u64,
    },
    Done,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ObservedBurst {
    outgoing_cells: u64,
    incoming_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NaturalSegment {
    direction: Direction,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NaturalBurst {
    outgoing_cells: u64,
    incoming_cells: u64,
}

/// Walkie-Talkie half-duplex burst-molding defense.
#[derive(Debug)]
pub struct WalkieTalkie {
    molded: Vec<BurstPair>,
    source_envelope: Vec<BurstPair>,
    source_batch_ends: Vec<usize>,
    batch_ends: HashSet<usize>,
    expected_application_batches: u64,
    observed_bursts: Vec<ObservedBurst>,
    turn: Turn,
    packet_size: u16,
    target_outgoing_cells: u64,
    target_incoming_cells: u64,
    observed_outgoing_cells: u64,
    observed_incoming_bytes: u64,
    outgoing_overflow_bytes: u64,
    incoming_overflow_bytes: u64,
    unattributed_incoming_bytes: u64,
    incoming_chaff_bytes: u64,
    control_only_crossings: u64,
    application_stream_crossing_bytes: u64,
    natural_outgoing_bytes: u64,
    natural_incoming_bytes: u64,
    natural_batch_segments: Vec<NaturalSegment>,
    source_envelope_overflow_cells: u64,
    application_batch_active: bool,
    application_batch_assigned: bool,
    application_batches_started: u64,
    application_batches_completed: u64,
    batch_lifecycle_errors: u64,
    now: Duration,
    application_complete: bool,
    retried_outgoing_events: u64,
}

impl WalkieTalkie {
    /// Load a version-two molded sequence from `config.molded`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, or strict JSON envelope
    /// is invalid, including when its packet size differs from the config.
    pub fn new(config: &WalkieTalkieConfig, max_udp_payload_size: u16) -> Result<Self> {
        Self::from_file(config, max_udp_payload_size, &config.molded)
    }

    /// Load a version-two molded sequence from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, or strict JSON envelope
    /// is invalid, including when its packet size differs from the config.
    pub fn from_file<P: AsRef<Path>>(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        path: P,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let input = fs::read_to_string(path)?;
        Self::from_json(config, max_udp_payload_size, &input)
    }

    /// Parse a version-two molded sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, unknown fields,
    /// empty/zero burst pairs, a packet-size mismatch, or unsafe limits.
    pub fn from_json(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        input: &str,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file: MoldedFile = serde_json::from_str(input)?;
        let selected = file.select_profile(config.packet_size, &config.workload_id)?;
        let (selected_source_envelope, selected_batch_ends) = if selected.real == config.workload_id
        {
            (&selected.source_envelopes.real, &selected.batch_ends.real)
        } else {
            (&selected.source_envelopes.decoy, &selected.batch_ends.decoy)
        };
        let expected_application_batches =
            u64::try_from(selected_batch_ends.len()).map_err(|_| {
                Error::InvalidConfig(
                    "Walkie-Talkie application batch count exceeds the diagnostic domain".into(),
                )
            })?;
        let molded = selected.bursts.clone();
        let source_envelope = selected_source_envelope.clone();
        let source_batch_ends = selected_batch_ends.clone();
        let batch_ends = selected.molded_batch_ends.iter().copied().collect();

        let first = molded[0];
        let observed_bursts = vec![ObservedBurst::default(); molded.len()];
        let target_outgoing_cells = molded.iter().map(|pair| u64::from(pair.outgoing)).sum();
        let target_incoming_cells = molded.iter().map(|pair| u64::from(pair.incoming)).sum();
        Ok(Self {
            molded,
            source_envelope,
            source_batch_ends,
            batch_ends,
            expected_application_batches,
            observed_bursts,
            turn: Turn::Outgoing {
                index: 0,
                to_emit: first.outgoing,
                awaiting: 0,
            },
            packet_size: config.packet_size,
            target_outgoing_cells,
            target_incoming_cells,
            observed_outgoing_cells: 0,
            observed_incoming_bytes: 0,
            outgoing_overflow_bytes: 0,
            incoming_overflow_bytes: 0,
            unattributed_incoming_bytes: 0,
            incoming_chaff_bytes: 0,
            control_only_crossings: 0,
            application_stream_crossing_bytes: 0,
            natural_outgoing_bytes: 0,
            natural_incoming_bytes: 0,
            natural_batch_segments: Vec::new(),
            source_envelope_overflow_cells: 0,
            application_batch_active: false,
            application_batch_assigned: false,
            application_batches_started: 0,
            application_batches_completed: 0,
            batch_lifecycle_errors: 0,
            now: Duration::ZERO,
            application_complete: false,
            retried_outgoing_events: 0,
        })
    }

    fn record_now(&mut self, at: Duration) {
        debug_assert!(
            at >= self.now,
            "the controller must deliver Walkie-Talkie timestamps monotonically"
        );
        self.now = at;
    }

    fn enter_incoming(&mut self, index: usize) {
        let Some(pair) = self.molded.get(index).copied() else {
            self.turn = Turn::Done;
            return;
        };
        self.turn = Turn::Incoming {
            index,
            credits_to_emit: pair.incoming,
            initial_credits_awaiting: 0,
            retry_bytes_to_emit: 0,
            retry_credits_awaiting: 0,
            credited_bytes_outstanding: 0,
            observed_remaining_bytes: u64::from(pair.incoming) * u64::from(self.packet_size),
        };
    }

    fn enter_next_outgoing(&mut self, index: usize) {
        let next_index = index.saturating_add(1);
        let Some(pair) = self.molded.get(next_index).copied() else {
            self.turn = Turn::Done;
            return;
        };
        if self.batch_ends.contains(&index)
            && self.application_batches_started < self.expected_application_batches
        {
            self.application_batch_assigned = false;
        }
        self.turn = Turn::Outgoing {
            index: next_index,
            to_emit: pair.outgoing,
            awaiting: 0,
        };
    }

    const fn awaiting_later_application_batch(&self) -> bool {
        // The runner dispatches the first globally ready batch before its
        // first defense poll.  Later outgoing turns can be entered from
        // inside a poll after observed ingress completes, so they must pause
        // until the runner has actually opened the next ready batch.
        self.application_batches_started > 0
            && self.application_batches_started < self.expected_application_batches
            && !self.application_batch_active
            && !self.application_batch_assigned
    }

    fn normalize_turn(&mut self) {
        loop {
            match self.turn {
                Turn::Outgoing {
                    index,
                    to_emit: 0,
                    awaiting: 0,
                } if !self.awaiting_later_application_batch() => {
                    self.enter_incoming(index);
                }
                Turn::Incoming {
                    index,
                    credits_to_emit: 0,
                    initial_credits_awaiting: 0,
                    retry_bytes_to_emit: 0,
                    retry_credits_awaiting: 0,
                    credited_bytes_outstanding: 0,
                    observed_remaining_bytes: 0,
                    ..
                } if !self.batch_ends.contains(&index) || !self.application_batch_active => {
                    self.enter_next_outgoing(index);
                }
                Turn::Outgoing { .. } | Turn::Incoming { .. } | Turn::Done => break,
            }
        }
    }

    fn on_incoming_payload(&mut self, bytes: u64, cover: bool) {
        self.observed_incoming_bytes = self.observed_incoming_bytes.saturating_add(bytes);
        if cover {
            self.incoming_chaff_bytes = self.incoming_chaff_bytes.saturating_add(bytes);
        }
        let Turn::Incoming {
            index,
            retry_bytes_to_emit,
            observed_remaining_bytes,
            ..
        } = &mut self.turn
        else {
            self.incoming_overflow_bytes = self.incoming_overflow_bytes.saturating_add(bytes);
            self.unattributed_incoming_bytes =
                self.unattributed_incoming_bytes.saturating_add(bytes);
            return;
        };

        self.observed_bursts[*index].incoming_bytes = self.observed_bursts[*index]
            .incoming_bytes
            .saturating_add(bytes);
        let attributed = bytes.min(*observed_remaining_bytes);
        *observed_remaining_bytes = observed_remaining_bytes.saturating_sub(bytes);
        if *observed_remaining_bytes == 0 {
            // A late response can satisfy the target before an armed retry is
            // handed to the controller.  Do not request credit that is no
            // longer needed; already emitted credit remains terminally
            // accounted and cannot be retracted.
            *retry_bytes_to_emit = 0;
        }
        self.incoming_overflow_bytes = self
            .incoming_overflow_bytes
            .saturating_add(bytes.saturating_sub(attributed));
        self.normalize_turn();
    }

    fn on_receive_credit_consumed(&mut self, bytes: u64) {
        if let Turn::Incoming {
            credited_bytes_outstanding,
            ..
        } = &mut self.turn
        {
            *credited_bytes_outstanding = credited_bytes_outstanding.saturating_sub(bytes);
        }
        self.normalize_turn();
    }

    fn on_application_bytes(&mut self, direction: Direction, bytes: u64) {
        if direction == Direction::Incoming && !matches!(self.turn, Turn::Incoming { .. }) {
            self.application_stream_crossing_bytes =
                self.application_stream_crossing_bytes.saturating_add(bytes);
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        match direction {
            Direction::Outgoing => {
                self.natural_outgoing_bytes = self.natural_outgoing_bytes.saturating_add(bytes);
            }
            Direction::Incoming => {
                self.natural_incoming_bytes = self.natural_incoming_bytes.saturating_add(bytes);
            }
        }
        if !self.application_batch_active {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
            return;
        }
        if let Some(segment) = self
            .natural_batch_segments
            .last_mut()
            .filter(|segment| segment.direction == direction)
        {
            segment.bytes = segment.bytes.saturating_add(bytes);
        } else {
            self.natural_batch_segments
                .push(NaturalSegment { direction, bytes });
        }
    }

    fn natural_batch_bursts(&self) -> (Vec<NaturalBurst>, bool) {
        let packet_size = u64::from(self.packet_size);
        let mut valid = self
            .natural_batch_segments
            .first()
            .is_some_and(|segment| segment.direction == Direction::Outgoing)
            && self
                .natural_batch_segments
                .iter()
                .any(|segment| segment.direction == Direction::Incoming);
        let mut bursts = Vec::new();
        let mut index = 0;
        while let Some(segment) = self.natural_batch_segments.get(index) {
            if segment.direction == Direction::Incoming {
                valid = false;
                bursts.push(NaturalBurst {
                    outgoing_cells: 0,
                    incoming_cells: segment.bytes.div_ceil(packet_size),
                });
                index += 1;
                continue;
            }
            let mut burst = NaturalBurst {
                outgoing_cells: segment.bytes.div_ceil(packet_size),
                incoming_cells: 0,
            };
            index += 1;
            if let Some(incoming) = self
                .natural_batch_segments
                .get(index)
                .filter(|candidate| candidate.direction == Direction::Incoming)
            {
                burst.incoming_cells = incoming.bytes.div_ceil(packet_size);
                index += 1;
            }
            bursts.push(burst);
        }
        (bursts, valid)
    }

    fn finish_natural_batch(&mut self) {
        let (observed, valid) = self.natural_batch_bursts();
        if !valid {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        let batch_index = usize::try_from(self.application_batches_completed).unwrap_or(usize::MAX);
        let expected_start = batch_index
            .checked_sub(1)
            .and_then(|previous| self.source_batch_ends.get(previous).copied())
            .map_or(0, |end| end.saturating_add(1));
        let expected = self
            .source_batch_ends
            .get(batch_index)
            .and_then(|end| self.source_envelope.get(expected_start..=(*end)))
            .unwrap_or(&[]);
        let overflow = observed
            .iter()
            .enumerate()
            .fold(0_u64, |overflow, (index, actual)| {
                let target = expected.get(index).copied().unwrap_or(BurstPair {
                    outgoing: 0,
                    incoming: 0,
                });
                overflow
                    .saturating_add(
                        actual
                            .outgoing_cells
                            .saturating_sub(u64::from(target.outgoing)),
                    )
                    .saturating_add(
                        actual
                            .incoming_cells
                            .saturating_sub(u64::from(target.incoming)),
                    )
            });
        self.source_envelope_overflow_cells =
            self.source_envelope_overflow_cells.saturating_add(overflow);
        self.natural_batch_segments.clear();
    }

    fn on_application_batch_started(&mut self) {
        if self.application_batch_active
            || self.application_batch_assigned
            || !matches!(self.turn, Turn::Outgoing { .. })
        {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        if !self.application_batch_active {
            self.natural_batch_segments.clear();
        }
        self.application_batch_active = true;
        self.application_batch_assigned = true;
        self.application_batches_started = self.application_batches_started.saturating_add(1);
    }

    fn on_application_batch_completed(&mut self) {
        if !self.application_batch_active {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
            return;
        }
        self.finish_natural_batch();
        self.application_batch_active = false;
        self.application_batches_completed = self.application_batches_completed.saturating_add(1);
        self.normalize_turn();
    }

    fn queue_retry(&mut self, bytes: u64) {
        let Turn::Incoming {
            retry_bytes_to_emit,
            observed_remaining_bytes,
            ..
        } = &mut self.turn
        else {
            return;
        };
        let available = observed_remaining_bytes.saturating_sub(*retry_bytes_to_emit);
        *retry_bytes_to_emit = retry_bytes_to_emit.saturating_add(bytes.min(available));
    }

    fn on_receive_credit_retired(&mut self, bytes: u64) {
        let retired = match &mut self.turn {
            Turn::Incoming {
                credited_bytes_outstanding,
                ..
            } => {
                let retired = bytes.min(*credited_bytes_outstanding);
                *credited_bytes_outstanding = credited_bytes_outstanding.saturating_sub(retired);
                retired
            }
            Turn::Outgoing { .. } | Turn::Done => 0,
        };
        self.queue_retry(retired);
        self.normalize_turn();
    }

    fn on_incoming_credit_resolution(&mut self, packet: Packet, outcome: EventOutcome) {
        let handled = match &mut self.turn {
            Turn::Incoming {
                initial_credits_awaiting,
                credited_bytes_outstanding,
                ..
            } if *initial_credits_awaiting > 0 => {
                *initial_credits_awaiting = initial_credits_awaiting.saturating_sub(1);
                if let EventOutcome::Satisfied { observed } = outcome {
                    *credited_bytes_outstanding =
                        credited_bytes_outstanding.saturating_add(u64::from(observed));
                }
                true
            }
            Turn::Incoming {
                retry_credits_awaiting,
                credited_bytes_outstanding,
                ..
            } if *retry_credits_awaiting > 0 => {
                *retry_credits_awaiting = retry_credits_awaiting.saturating_sub(1);
                if let EventOutcome::Satisfied { observed } = outcome {
                    *credited_bytes_outstanding =
                        credited_bytes_outstanding.saturating_add(u64::from(observed));
                }
                true
            }
            Turn::Outgoing { .. } | Turn::Incoming { .. } | Turn::Done => false,
        };
        if handled && matches!(outcome, EventOutcome::Missed(_)) {
            // Only a terminally missed increment is safe to retry here.
            // Advertised credit remains in flight until payload consumes it
            // or the controller explicitly retires its unused stream offset.
            self.queue_retry(u64::from(packet.length()));
        }
        self.normalize_turn();
    }

    fn on_outgoing_resolution(&mut self, outcome: EventOutcome) {
        let Turn::Outgoing {
            index,
            to_emit,
            awaiting,
        } = &mut self.turn
        else {
            return;
        };
        if *awaiting == 0 {
            return;
        }

        *awaiting = awaiting.saturating_sub(1);
        match outcome {
            EventOutcome::Satisfied { observed } => {
                self.observed_outgoing_cells = self.observed_outgoing_cells.saturating_add(1);
                self.observed_bursts[*index].outgoing_cells = self.observed_bursts[*index]
                    .outgoing_cells
                    .saturating_add(1);
                self.outgoing_overflow_bytes = self
                    .outgoing_overflow_bytes
                    .saturating_add(u64::from(observed.saturating_sub(self.packet_size)));
            }
            EventOutcome::Missed(_) => {
                *to_emit = to_emit.saturating_add(1);
                self.retried_outgoing_events = self.retried_outgoing_events.saturating_add(1);
            }
        }
        self.normalize_turn();
    }

    fn next_internal_deadline(&self) -> Option<Duration> {
        match self.turn {
            Turn::Outgoing { .. } if self.awaiting_later_application_batch() => None,
            Turn::Outgoing {
                to_emit, awaiting, ..
            } => (to_emit > 0 || awaiting == 0).then_some(self.now),
            Turn::Incoming {
                index,
                credits_to_emit,
                retry_bytes_to_emit,
                observed_remaining_bytes,
                retry_credits_awaiting,
                initial_credits_awaiting,
                credited_bytes_outstanding,
                ..
            } => (credits_to_emit > 0
                || retry_bytes_to_emit > 0
                || observed_remaining_bytes == 0
                    && initial_credits_awaiting == 0
                    && retry_credits_awaiting == 0
                    && credited_bytes_outstanding == 0
                    && (!self.batch_ends.contains(&index) || !self.application_batch_active))
                .then_some(self.now),
            Turn::Done => None,
        }
    }
}

impl Defense for WalkieTalkie {
    fn observe(&mut self, signal: DefenseSignal) {
        let at = signal.at;
        self.record_now(at);

        match signal.kind {
            SignalKind::Resolved { packet, outcome }
                if packet.direction() == Direction::Outgoing
                    && packet.length() == self.packet_size =>
            {
                self.on_outgoing_resolution(outcome);
            }
            SignalKind::Resolved { packet, outcome }
                if packet.direction() == Direction::Incoming =>
            {
                self.on_incoming_credit_resolution(packet, outcome);
            }
            SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover,
            } => self.on_incoming_payload(bytes, cover),
            SignalKind::ReceiveCreditRetired { bytes } => {
                self.on_receive_credit_retired(bytes);
            }
            SignalKind::ReceiveCreditConsumed { bytes } => {
                self.on_receive_credit_consumed(bytes);
            }
            SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes,
                cover: false,
            } if matches!(self.turn, Turn::Incoming { .. }) => {
                self.application_stream_crossing_bytes =
                    self.application_stream_crossing_bytes.saturating_add(bytes);
            }
            SignalKind::ApplicationBatchStarted => self.on_application_batch_started(),
            SignalKind::ApplicationBatchCompleted => self.on_application_batch_completed(),
            SignalKind::ApplicationComplete => self.application_complete = true,
            SignalKind::Wire {
                direction: Direction::Outgoing,
                ..
            } if matches!(self.turn, Turn::Incoming { .. }) => {
                // STREAM data is transport-gated throughout an incoming turn.
                // Any client datagram that still crosses is therefore necessary
                // ACK/path/control traffic, which the adaptation permits.
                self.control_only_crossings = self.control_only_crossings.saturating_add(1);
            }
            SignalKind::Wire { .. }
            | SignalKind::ClassifiedWire { .. }
            | SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                ..
            }
            | SignalKind::Capacity(_)
            | SignalKind::TrafficMorphingEgress { .. }
            | SignalKind::Resolved { .. } => {}
        }
    }

    fn observe_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
        self.record_now(at);
        self.on_application_bytes(direction, bytes);
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        let at = elapsed;
        self.record_now(at);
        self.normalize_turn();
        if self.awaiting_later_application_batch() && matches!(self.turn, Turn::Outgoing { .. }) {
            return None;
        }

        loop {
            match &mut self.turn {
                Turn::Outgoing {
                    to_emit, awaiting, ..
                } if *to_emit > 0 => {
                    let packet = Packet::new(at, Direction::Outgoing, self.packet_size).ok()?;
                    *to_emit = to_emit.saturating_sub(1);
                    *awaiting = awaiting.saturating_add(1);
                    return Some(packet);
                }
                Turn::Outgoing { awaiting, .. } if *awaiting > 0 => return None,
                Turn::Outgoing { .. } => {
                    self.normalize_turn();
                    if matches!(self.turn, Turn::Outgoing { .. }) {
                        return None;
                    }
                }
                Turn::Incoming {
                    credits_to_emit,
                    initial_credits_awaiting,
                    ..
                } if *credits_to_emit > 0 => {
                    let packet = Packet::new(at, Direction::Incoming, self.packet_size).ok()?;
                    *credits_to_emit = credits_to_emit.saturating_sub(1);
                    *initial_credits_awaiting = initial_credits_awaiting.saturating_add(1);
                    return Some(packet);
                }
                Turn::Incoming {
                    retry_bytes_to_emit,
                    retry_credits_awaiting,
                    ..
                } if *retry_bytes_to_emit > 0 => {
                    let length = (*retry_bytes_to_emit).min(u64::from(self.packet_size));
                    let length = u16::try_from(length).ok()?;
                    let packet = Packet::new(at, Direction::Incoming, length).ok()?;
                    *retry_bytes_to_emit = retry_bytes_to_emit.saturating_sub(u64::from(length));
                    *retry_credits_awaiting = retry_credits_awaiting.saturating_add(1);
                    return Some(packet);
                }
                Turn::Incoming { .. } => {
                    self.normalize_turn();
                    if matches!(self.turn, Turn::Incoming { .. }) {
                        return None;
                    }
                }
                Turn::Done => return None,
            }
        }
    }

    fn next_event_at(&self) -> Option<Duration> {
        self.next_internal_deadline()
    }

    fn is_complete(&self) -> bool {
        self.application_complete
            && !self.application_batch_active
            && matches!(self.turn, Turn::Done)
    }

    fn is_outgoing_complete(&self) -> bool {
        match self.turn {
            Turn::Done => true,
            Turn::Outgoing {
                index,
                to_emit,
                awaiting,
                ..
            } => {
                to_emit == 0
                    && awaiting == 0
                    && self
                        .molded
                        .iter()
                        .skip(index.saturating_add(1))
                        .all(|pair| pair.outgoing == 0)
            }
            Turn::Incoming { index, .. } => self
                .molded
                .iter()
                .skip(index.saturating_add(1))
                .all(|pair| pair.outgoing == 0),
        }
    }

    fn can_release_chaff_send_shaping(&self) -> bool {
        matches!(self.turn, Turn::Done)
    }

    fn can_start_application_batch(&self) -> bool {
        self.application_batches_started < self.expected_application_batches
            && !self.application_batch_active
            && !self.application_batch_assigned
            && matches!(self.turn, Turn::Outgoing { .. })
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn diagnostics(&self) -> DefenseDiagnostics {
        let incoming_shortfall = match self.turn {
            Turn::Incoming {
                index,
                observed_remaining_bytes,
                ..
            } => observed_remaining_bytes.saturating_add(
                self.molded
                    .iter()
                    .skip(index.saturating_add(1))
                    .map(|pair| u64::from(pair.incoming) * u64::from(self.packet_size))
                    .sum(),
            ),
            Turn::Outgoing { index, .. } => self
                .molded
                .iter()
                .skip(index)
                .map(|pair| u64::from(pair.incoming) * u64::from(self.packet_size))
                .sum(),
            Turn::Done => 0,
        };
        let packet_size = u64::from(self.packet_size);
        let observed_incoming_cells = self.observed_incoming_bytes.div_ceil(packet_size);
        let outgoing_shortfall_cells = self
            .target_outgoing_cells
            .saturating_sub(self.observed_outgoing_cells);
        let outgoing_overflow_cells = self
            .observed_outgoing_cells
            .saturating_sub(self.target_outgoing_cells)
            .saturating_add(self.outgoing_overflow_bytes.div_ceil(packet_size));
        let incoming_shortfall_cells = incoming_shortfall.div_ceil(packet_size);
        let incoming_overflow_cells = self.incoming_overflow_bytes.div_ceil(packet_size);
        let burst_realization: Vec<_> = self
            .molded
            .iter()
            .zip(&self.observed_bursts)
            .enumerate()
            .map(|(index, (target, observed))| WalkieTalkieBurstDiagnostics {
                index,
                target_outgoing_cells: u64::from(target.outgoing),
                target_incoming_cells: u64::from(target.incoming),
                observed_outgoing_cells: observed.outgoing_cells,
                observed_incoming_cells: observed.incoming_bytes.div_ceil(packet_size),
            })
            .collect();
        let target_observed_l1 = self
            .target_outgoing_cells
            .abs_diff(self.observed_outgoing_cells)
            .saturating_add(self.target_incoming_cells.abs_diff(observed_incoming_cells));
        let target_observed_burst_l1 = burst_realization
            .iter()
            .fold(0_u64, |distance, burst| {
                distance
                    .saturating_add(
                        burst
                            .target_outgoing_cells
                            .abs_diff(burst.observed_outgoing_cells),
                    )
                    .saturating_add(
                        burst
                            .target_incoming_cells
                            .abs_diff(burst.observed_incoming_cells),
                    )
            })
            .saturating_add(self.outgoing_overflow_bytes.div_ceil(packet_size))
            .saturating_add(self.unattributed_incoming_bytes.div_ceil(packet_size));
        DefenseDiagnostics {
            retried_outgoing_events: self.retried_outgoing_events,
            walkie_talkie_target_outgoing_cells: self.target_outgoing_cells,
            walkie_talkie_target_incoming_cells: self.target_incoming_cells,
            walkie_talkie_observed_outgoing_cells: self.observed_outgoing_cells,
            walkie_talkie_observed_incoming_cells: observed_incoming_cells,
            walkie_talkie_outgoing_shortfall_cells: outgoing_shortfall_cells,
            walkie_talkie_incoming_shortfall_cells: incoming_shortfall_cells,
            walkie_talkie_outgoing_overflow_cells: outgoing_overflow_cells,
            walkie_talkie_incoming_overflow_cells: incoming_overflow_cells,
            walkie_talkie_incoming_shortfall_bytes: incoming_shortfall,
            walkie_talkie_incoming_chaff_bytes: self.incoming_chaff_bytes,
            walkie_talkie_target_observed_cell_l1: target_observed_l1,
            walkie_talkie_target_observed_burst_l1: target_observed_burst_l1,
            walkie_talkie_control_only_crossings: self.control_only_crossings,
            walkie_talkie_application_stream_crossing_bytes: self.application_stream_crossing_bytes,
            walkie_talkie_natural_outgoing_bytes: self.natural_outgoing_bytes,
            walkie_talkie_natural_incoming_bytes: self.natural_incoming_bytes,
            walkie_talkie_source_envelope_overflow_cells: self.source_envelope_overflow_cells,
            walkie_talkie_burst_realization: burst_realization,
            walkie_talkie_expected_application_batches: self.expected_application_batches,
            walkie_talkie_observed_application_batches: self.application_batches_started,
            walkie_talkie_application_batch_overflow: self
                .application_batches_started
                .saturating_sub(self.expected_application_batches),
            walkie_talkie_application_batches_completed: self.application_batches_completed,
            walkie_talkie_batch_lifecycle_errors: self.batch_lifecycle_errors,
            walkie_talkie_application_batch_active: self.application_batch_active,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use super::WalkieTalkie;
    use crate::{
        Defense as _, DefenseMode, DefenseSignal, Direction, EventOutcome, MissedSlotReason,
        Packet, SignalKind, WalkieTalkieBurstDiagnostics, WalkieTalkieConfig, defense::drive,
    };

    fn config(packet_size: u16) -> WalkieTalkieConfig {
        WalkieTalkieConfig {
            molded: "test-molded.json".into(),
            workload_id: "real page".into(),
            packet_size,
        }
    }

    fn molded(bursts: &str) -> String {
        molded_pair(bursts, bursts)
    }

    fn parse_test_bursts(bursts: &str) -> (Vec<super::BurstPair>, Vec<usize>) {
        let mut records: Vec<serde_json::Value> =
            serde_json::from_str(bursts).expect("test bursts are valid JSON");
        let mut batch_ends = Vec::new();
        for (index, record) in records.iter_mut().enumerate() {
            let record = record.as_object_mut().expect("test burst is an object");
            let batch_end = record
                .remove("batch_end")
                .is_none_or(|value| value.as_bool().expect("boolean batch_end"));
            if batch_end {
                batch_ends.push(index);
            }
        }
        let pairs: Vec<super::BurstPair> =
            serde_json::from_value(serde_json::Value::Array(records))
                .expect("enriched test bursts are valid");
        (pairs, batch_ends)
    }

    fn molded_pair(real: &str, decoy: &str) -> String {
        let (real, real_batch_ends) = parse_test_bursts(real);
        let (decoy, decoy_batch_ends) = parse_test_bursts(decoy);
        let (bursts, molded_batch_ends) =
            super::mold(&real, &real_batch_ends, &decoy, &decoy_batch_ends);
        let matching_cost_packets = super::total_packets(&bursts)
            .expect("molded test packet count")
            .checked_mul(2)
            .and_then(|value| {
                value.checked_sub(
                    super::total_packets(&real).expect("real test packet count")
                        + super::total_packets(&decoy).expect("decoy test packet count"),
                )
            })
            .expect("test matching cost");
        let total_scheduled_bytes = bursts.iter().fold(0_u64, |total, pair| {
            total + (u64::from(pair.outgoing) + u64::from(pair.incoming)) * 100
        });
        let real = serde_json::to_string(&real).expect("serialize real test bursts");
        let decoy = serde_json::to_string(&decoy).expect("serialize decoy test bursts");
        let bursts = serde_json::to_string(&bursts).expect("serialize molded test bursts");
        format!(
            r#"{{
                "adaptation": "qcsd-client-only",
                "burst_definition": "global-application-batch-direction-transitions",
                "cell_byte_domain": "http3-request-stream-offset.bytes",
                "schema_version": 2,
                "generated_by": "test",
                "matching_algorithm": "minimum-cost-one-to-one",
                "paper_equivalent": false,
                "packet_size": 100,
                "training_split": "train",
                "profiles": [{{
                    "real": "real page",
                    "decoy": "decoy page",
                    "matching_cost_packets": {matching_cost_packets},
                    "training_inputs": {{
                        "real": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                        "decoy": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                    }},
                    "variation": {{
                        "real": {{
                            "visit_count": 1,
                            "varying_components": 0,
                            "maximum_component_spread": 0
                        }},
                        "decoy": {{
                            "visit_count": 1,
                            "varying_components": 0,
                            "maximum_component_spread": 0
                        }}
                    }},
                    "source_envelopes": {{"real": {real}, "decoy": {decoy}}},
                    "batch_ends": {{
                        "real": {real_batch_ends:?},
                        "decoy": {decoy_batch_ends:?}
                    }},
                    "molded_batch_ends": {molded_batch_ends:?},
                    "total_scheduled_bytes": {total_scheduled_bytes},
                    "bursts": {bursts}
                }}]
            }}"#
        )
    }

    fn resolve(defense: &mut WalkieTalkie, at_us: u64, packet: Packet, outcome: EventOutcome) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::Resolved { packet, outcome },
        });
    }

    fn incoming_wire(defense: &mut WalkieTalkie, at_us: u64) {
        incoming_payload(defense, at_us, 100, false);
    }

    fn incoming_payload(defense: &mut WalkieTalkie, at_us: u64, bytes: u64, cover: bool) {
        let pending_length = match defense.turn {
            super::Turn::Incoming {
                initial_credits_awaiting,
                ..
            } if initial_credits_awaiting > 0 => Some(defense.packet_size),
            super::Turn::Incoming {
                retry_credits_awaiting,
                ..
            } if retry_credits_awaiting > 0 => {
                Some(u16::try_from(bytes.min(u64::from(defense.packet_size))).expect("cell bytes"))
            }
            super::Turn::Outgoing { .. } | super::Turn::Incoming { .. } | super::Turn::Done => None,
        };
        if let Some(length) = pending_length {
            let packet = Packet::new(Duration::from_micros(at_us), Direction::Incoming, length)
                .expect("pending incoming credit");
            resolve(
                defense,
                at_us,
                packet,
                EventOutcome::Satisfied { observed: length },
            );
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ReceiveCreditConsumed { bytes },
        });
    }

    fn retire_credit(defense: &mut WalkieTalkie, at_us: u64, bytes: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ReceiveCreditRetired { bytes },
        });
    }

    fn application_batch_started(defense: &mut WalkieTalkie, at_us: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ApplicationBatchStarted,
        });
    }

    fn application_batch_completed(defense: &mut WalkieTalkie, at_us: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ApplicationBatchCompleted,
        });
    }

    fn application_bytes(defense: &mut WalkieTalkie, at_us: u64, direction: Direction, bytes: u64) {
        defense.observe_application_bytes(Duration::from_micros(at_us), direction, bytes);
    }

    #[test]
    fn loader_rejects_unknown_fields_wrong_versions_and_packet_size_mismatch() {
        let unknown = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            r#""schema_version": 2,"#,
            r#""schema_version": 2, "unexpected": true,"#,
        );
        assert!(WalkieTalkie::from_json(&config(100), 1_200, &unknown).is_err());

        let wrong_version = molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            .replace(r#""schema_version": 2"#, r#""schema_version": 1"#);
        assert!(WalkieTalkie::from_json(&config(100), 1_200, &wrong_version).is_err());

        assert!(
            WalkieTalkie::from_json(
                &config(99),
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );

        let wrong_total = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            r#""total_scheduled_bytes": 200"#,
            r#""total_scheduled_bytes": 199"#,
        );
        assert!(WalkieTalkie::from_json(&config(100), 1_200, &wrong_total).is_err());

        let same_label = molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            .replace(r#""decoy": "decoy page""#, r#""decoy": "real page""#);
        assert!(WalkieTalkie::from_json(&config(100), 1_200, &same_label).is_err());

        let mut missing = config(100);
        missing.workload_id = "missing workload".into();
        assert!(
            WalkieTalkie::from_json(
                &missing,
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );

        let mut unbound = config(100);
        unbound.workload_id.clear();
        assert!(
            WalkieTalkie::from_json(
                &unbound,
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );
    }

    #[test]
    fn batch_aware_mold_does_not_flatten_components_across_application_batches() {
        let (real, real_batch_ends) = parse_test_bursts(
            r#"[
                {"outgoing": 1, "incoming": 1},
                {"outgoing": 2, "incoming": 2, "batch_end": false},
                {"outgoing": 3, "incoming": 3}
            ]"#,
        );
        let (decoy, decoy_batch_ends) = parse_test_bursts(
            r#"[
                {"outgoing": 4, "incoming": 4, "batch_end": false},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]"#,
        );

        let (batch_aware, common_batch_ends) =
            super::mold(&real, &real_batch_ends, &decoy, &decoy_batch_ends);
        let flattened: Vec<_> = real
            .iter()
            .zip(&decoy)
            .map(|(real, decoy)| super::BurstPair {
                outgoing: real.outgoing.max(decoy.outgoing),
                incoming: real.incoming.max(decoy.incoming),
            })
            .collect();

        assert_eq!(
            batch_aware,
            [
                super::BurstPair {
                    outgoing: 4,
                    incoming: 4,
                },
                super::BurstPair {
                    outgoing: 5,
                    incoming: 5,
                },
                super::BurstPair {
                    outgoing: 6,
                    incoming: 6,
                },
                super::BurstPair {
                    outgoing: 3,
                    incoming: 3,
                },
            ]
        );
        assert_eq!(common_batch_ends, [1, 3]);
        assert_ne!(batch_aware, flattened);
    }

    #[test]
    fn loader_rejects_missing_or_flattened_common_batch_boundaries() {
        let valid = molded_pair(
            r#"[
                {"outgoing": 1, "incoming": 1},
                {"outgoing": 2, "incoming": 2, "batch_end": false},
                {"outgoing": 3, "incoming": 3}
            ]"#,
            r#"[
                {"outgoing": 4, "incoming": 4, "batch_end": false},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]"#,
        );
        let mut missing: serde_json::Value =
            serde_json::from_str(&valid).expect("valid profile JSON");
        missing["profiles"][0]
            .as_object_mut()
            .expect("profile object")
            .remove("molded_batch_ends");
        assert!(
            WalkieTalkie::from_json(&config(100), 1_200, &missing.to_string()).is_err(),
            "legacy profiles without explicit common boundaries must be rejected"
        );

        let mut flattened: serde_json::Value =
            serde_json::from_str(&valid).expect("valid profile JSON");
        let profile = flattened["profiles"][0]
            .as_object_mut()
            .expect("profile object");
        profile.insert(
            "bursts".into(),
            serde_json::json!([
                {"outgoing": 4, "incoming": 4},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]),
        );
        profile.insert("molded_batch_ends".into(), serde_json::json!([1, 2]));
        profile.insert("matching_cost_packets".into(), serde_json::json!(18));
        profile.insert("total_scheduled_bytes".into(), serde_json::json!(3_000));
        assert!(
            WalkieTalkie::from_json(&config(100), 1_200, &flattened.to_string()).is_err(),
            "strict validation must recompute the batch-aware mould"
        );
    }

    #[test]
    fn either_side_of_one_symmetric_pair_selects_the_same_mold() {
        let input = molded_pair(
            r#"[
                {"outgoing": 2, "incoming": 3},
                {"outgoing": 1, "incoming": 1}
            ]"#,
            r#"[
                {"outgoing": 3, "incoming": 2, "batch_end": false},
                {"outgoing": 4, "incoming": 4},
                {"outgoing": 1, "incoming": 2}
            ]"#,
        );
        let real = WalkieTalkie::from_json(&config(100), 1_200, &input).expect("real binding");
        let mut decoy_config = config(100);
        decoy_config.workload_id = "decoy page".into();
        let decoy = WalkieTalkie::from_json(&decoy_config, 1_200, &input).expect("decoy binding");
        assert_eq!(real.molded, decoy.molded);
        assert_eq!(real.batch_ends, decoy.batch_ends);
        assert_eq!(real.batch_ends, HashSet::from([1, 2]));
        assert_eq!(real.expected_application_batches, 2);
        assert_eq!(decoy.expected_application_batches, 2);
    }

    #[test]
    fn scheduled_byte_overflow_is_rejected() {
        let bursts = vec![
            super::BurstPair {
                outgoing: u32::MAX,
                incoming: u32::MAX,
            };
            32_769
        ];
        let file = super::MoldedFile {
            adaptation: "qcsd-client-only".into(),
            burst_definition: "global-application-batch-direction-transitions".into(),
            cell_byte_domain: "http3-request-stream-offset.bytes".into(),
            schema_version: 2,
            generated_by: "test".into(),
            matching_algorithm: "minimum-cost-one-to-one".into(),
            paper_equivalent: false,
            packet_size: u16::MAX,
            training_split: "train".into(),
            profiles: vec![super::MoldedProfile {
                real: "real".into(),
                decoy: "decoy".into(),
                matching_cost_packets: 0,
                training_inputs: super::PairTrainingInputs {
                    real: vec!["a".repeat(64)],
                    decoy: vec!["b".repeat(64)],
                },
                variation: super::PairVariation {
                    real: super::ProfileVariation {
                        visit_count: 1,
                        varying_components: 0,
                        maximum_component_spread: 0,
                    },
                    decoy: super::ProfileVariation {
                        visit_count: 1,
                        varying_components: 0,
                        maximum_component_spread: 0,
                    },
                },
                source_envelopes: super::SourceEnvelopes {
                    real: bursts.clone(),
                    decoy: bursts.clone(),
                },
                batch_ends: super::PairBatchEnds {
                    real: vec![bursts.len() - 1],
                    decoy: vec![bursts.len() - 1],
                },
                molded_batch_ends: vec![bursts.len() - 1],
                total_scheduled_bytes: 0,
                bursts,
            }],
        };

        assert!(file.select_profile(u16::MAX, "real").is_err());
    }

    #[test]
    fn incoming_turn_never_emits_an_outgoing_defense_event() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 2, "incoming": 2},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");

        let first = defense.next_event(Duration::ZERO).expect("outgoing one");
        let second = defense.next_event(Duration::ZERO).expect("outgoing two");
        assert_eq!(first.direction(), Direction::Outgoing);
        assert_eq!(second.direction(), Direction::Outgoing);
        assert_eq!(defense.next_event(Duration::ZERO), None);

        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Satisfied { observed: 100 },
        );
        resolve(
            &mut defense,
            2,
            second,
            EventOutcome::Satisfied { observed: 100 },
        );

        let incoming_one = defense
            .next_event(Duration::from_micros(2))
            .expect("incoming credit one");
        let incoming_two = defense
            .next_event(Duration::from_micros(2))
            .expect("incoming credit two");
        assert_eq!(incoming_one.direction(), Direction::Incoming);
        assert_eq!(incoming_two.direction(), Direction::Incoming);
        assert_eq!(defense.next_event(Duration::from_micros(2)), None);

        incoming_wire(&mut defense, 3);
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        incoming_wire(&mut defense, 4);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(4))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
        assert_eq!(defense.mode(), DefenseMode::ChaffAndShape);
    }

    #[test]
    fn outgoing_wire_during_an_incoming_turn_is_a_control_only_crossing() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Wire {
                direction: Direction::Outgoing,
                length: 77,
            },
        });
        assert_eq!(
            defense.diagnostics().walkie_talkie_control_only_crossings,
            1
        );
    }

    #[test]
    fn application_stream_bytes_during_incoming_turn_are_integrity_failures() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes: 17,
                cover: false,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes: 23,
                cover: true,
            },
        });

        assert_eq!(
            defense
                .diagnostics()
                .walkie_talkie_application_stream_crossing_bytes,
            17
        );
    }

    #[test]
    fn missed_outgoing_events_are_retried_before_the_turn_advances() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        let first = defense.next_event(Duration::ZERO).expect("outgoing");

        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Missed(MissedSlotReason::NoEndpoint),
        );
        let retry = defense.next_event(Duration::from_micros(1)).expect("retry");
        assert_eq!(retry.direction(), Direction::Outgoing);
        assert_eq!(defense.diagnostics().retried_outgoing_events, 1);
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);

        resolve(
            &mut defense,
            2,
            retry,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(2))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
    }

    #[test]
    fn incoming_shortage_never_advances_on_elapsed_time() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 2},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 10);

        assert_eq!(defense.next_event(Duration::from_micros(109)), None);
        assert_eq!(defense.next_event(Duration::from_micros(999)), None);
        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            200
        );
        incoming_wire(&mut defense, 60_000_001);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_001))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn incoming_turn_waits_for_both_payload_budget_and_application_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");

        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        assert!(!defense.can_start_application_batch());

        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);

        defense.observe(DefenseSignal {
            at: Duration::from_secs(60),
            kind: SignalKind::ApplicationComplete,
        });
        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        assert!(!defense.can_start_application_batch());

        application_batch_completed(&mut defense, 60_000_001);
        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(60_000_001)), None);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 2);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(!diagnostics.walkie_talkie_application_batch_active);

        application_batch_started(&mut defense, 60_000_002);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_002))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn application_fin_retries_exact_residual_credit_for_each_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 2},
                    {"outgoing": 1, "incoming": 2}
                ]"#,
            ),
        )
        .expect("two-batch molded sequence");

        for (batch, natural_incoming, residual) in [(0_u64, 150_u64, 50_u16), (1, 175, 25)] {
            let at = batch * 10;
            assert!(defense.can_start_application_batch());
            application_batch_started(&mut defense, at);
            application_bytes(&mut defense, at, Direction::Outgoing, 100);

            let outgoing = defense
                .next_event(Duration::from_micros(at))
                .expect("batch outgoing cell");
            resolve(
                &mut defense,
                at + 1,
                outgoing,
                EventOutcome::Satisfied { observed: 100 },
            );

            let incoming: Vec<_> = std::iter::repeat_with(|| {
                defense
                    .next_event(Duration::from_micros(at + 1))
                    .expect("initial incoming credit")
            })
            .take(2)
            .collect();
            for packet in incoming {
                resolve(
                    &mut defense,
                    at + 2,
                    packet,
                    EventOutcome::Satisfied { observed: 100 },
                );
            }

            incoming_payload(&mut defense, at + 3, natural_incoming, false);
            application_bytes(&mut defense, at + 3, Direction::Incoming, natural_incoming);
            retire_credit(&mut defense, at + 4, u64::from(residual));
            application_batch_completed(&mut defense, at + 4);

            let retry = defense
                .next_event(Duration::from_micros(at + 4))
                .expect("FIN-armed exact residual credit");
            assert_eq!(retry.direction(), Direction::Incoming);
            assert_eq!(retry.length(), residual);
            assert_eq!(defense.next_event(Duration::from_micros(at + 4)), None);

            // Encoding receive credit is terminal slot evidence, not observed
            // response traffic, and therefore cannot advance or self-rearm.
            resolve(
                &mut defense,
                at + 5,
                retry,
                EventOutcome::Satisfied { observed: residual },
            );
            assert_eq!(defense.next_event(Duration::from_micros(at + 5)), None);
            assert!(!defense.can_start_application_batch());

            incoming_payload(&mut defense, at + 6, u64::from(residual), true);
        }

        defense.observe(DefenseSignal {
            at: Duration::from_micros(17),
            kind: SignalKind::ApplicationComplete,
        });
        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 75);
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 2);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 2);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
    }

    #[test]
    fn batch_completion_never_regrants_credit_that_is_still_in_flight() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("single-batch molded sequence");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 50);

        let credits: Vec<_> = std::iter::repeat_with(|| {
            defense
                .next_event(Duration::ZERO)
                .expect("initial incoming credit")
        })
        .take(2)
        .collect();
        for credit in credits {
            resolve(
                &mut defense,
                1,
                credit,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        incoming_payload(&mut defense, 2, 50, false);
        application_bytes(&mut defense, 2, Direction::Incoming, 50);
        application_batch_completed(&mut defense, 3);

        // The 150-byte residual is already backed by advertised credit. Batch
        // completion alone cannot prove that this allowance was lost.
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        retire_credit(&mut defense, 4, 50);
        let retry = defense
            .next_event(Duration::from_micros(4))
            .expect("only retired credit is retried");
        assert_eq!(retry.length(), 50);
        assert_eq!(defense.next_event(Duration::from_micros(4)), None);
        resolve(
            &mut defense,
            5,
            retry,
            EventOutcome::Satisfied { observed: 50 },
        );
        incoming_payload(&mut defense, 6, 150, true);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(7),
            kind: SignalKind::ApplicationComplete,
        });

        let diagnostics = defense.diagnostics();
        assert!(defense.is_complete());
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
    }

    #[test]
    fn initial_allowance_does_not_retire_scheduled_credit_early() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("single incoming cell");
        let credit = defense.next_event(Duration::ZERO).expect("incoming credit");
        resolve(
            &mut defense,
            1,
            credit,
            EventOutcome::Satisfied { observed: 100 },
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 100,
                cover: true,
            },
        });
        // Raw offsets 0..16 came from the initial transport allowance. Only
        // 84 bytes intersect the scheduled [16, 116) range.
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 84 },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(!defense.is_complete());
        assert_eq!(defense.next_event(Duration::from_secs(60)), None);

        retire_credit(&mut defense, 60_000_001, 16);
        assert!(defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            0
        );
    }

    #[test]
    fn missed_residual_credit_retries_only_after_terminal_failure_observation() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("single-batch molded sequence");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing cell");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        let initial = defense
            .next_event(Duration::from_micros(1))
            .expect("initial incoming credit");
        resolve(
            &mut defense,
            2,
            initial,
            EventOutcome::Satisfied { observed: 100 },
        );
        incoming_payload(&mut defense, 3, 60, false);
        application_bytes(&mut defense, 3, Direction::Incoming, 60);
        retire_credit(&mut defense, 4, 40);
        application_batch_completed(&mut defense, 4);

        let first_retry = defense
            .next_event(Duration::from_micros(4))
            .expect("first exact residual attempt");
        assert_eq!(first_retry.length(), 40);
        assert_eq!(defense.next_event(Duration::from_micros(4)), None);
        resolve(
            &mut defense,
            5,
            first_retry,
            EventOutcome::Missed(MissedSlotReason::InsufficientIncomingCapacity),
        );
        let second_retry = defense
            .next_event(Duration::from_micros(5))
            .expect("failed residual credit is retryable");
        assert_eq!(second_retry.length(), 40);
        resolve(
            &mut defense,
            6,
            second_retry,
            EventOutcome::Satisfied { observed: 40 },
        );

        for at in [6, 100, 10_000] {
            assert_eq!(defense.next_event(Duration::from_micros(at)), None);
        }
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            40
        );
        incoming_payload(&mut defense, 10_001, 40, true);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(10_002),
            kind: SignalKind::ApplicationComplete,
        });
        assert!(defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            0
        );
    }

    #[test]
    fn direction_transitions_inside_one_batch_do_not_open_a_new_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1, "batch_end": false},
                    {"outgoing": 1, "incoming": 1, "batch_end": true}
                ]"#,
            ),
        )
        .expect("valid multi-burst application batch");
        application_batch_started(&mut defense, 0);

        let first_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("first outgoing cell");
        resolve(
            &mut defense,
            0,
            first_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense.next_event(Duration::ZERO),
            Packet::new(Duration::ZERO, Direction::Incoming, 100).ok()
        );
        incoming_wire(&mut defense, 0);

        assert!(!defense.can_start_application_batch());
        let second_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("same batch's second outgoing burst");
        resolve(
            &mut defense,
            0,
            second_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense.next_event(Duration::ZERO),
            Packet::new(Duration::ZERO, Direction::Incoming, 100).ok()
        );
        incoming_wire(&mut defense, 0);
        assert!(!matches!(defense.turn, super::Turn::Done));

        application_batch_completed(&mut defense, 0);
        assert!(matches!(defense.turn, super::Turn::Done));
    }

    #[test]
    fn longer_decoy_suffix_is_chaff_only_and_batch_overflow_is_diagnostic() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded_pair(
                r#"[{"outgoing": 1, "incoming": 1}]"#,
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 2, "incoming": 1}
                ]"#,
            ),
        )
        .expect("asymmetric molded sequence");

        assert_eq!(defense.source_batch_ends, [0]);
        assert_eq!(defense.batch_ends.len(), 2);
        assert!(defense.batch_ends.contains(&0));
        assert!(defense.batch_ends.contains(&1));
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let first = defense.next_event(Duration::ZERO).expect("source outgoing");
        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);

        assert!(!defense.can_start_application_batch());
        for at_us in [3, 4] {
            let suffix = defense
                .next_event(Duration::from_micros(at_us))
                .expect("decoy-only outgoing suffix");
            assert_eq!(suffix.direction(), Direction::Outgoing);
            resolve(
                &mut defense,
                at_us,
                suffix,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        assert_eq!(
            defense
                .next_event(Duration::from_micros(4))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 5);
        assert!(matches!(defense.turn, super::Turn::Done));
        assert!(!defense.can_start_application_batch());

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);

        application_batch_started(&mut defense, 6);
        let overflow = defense.diagnostics();
        assert_eq!(overflow.walkie_talkie_observed_application_batches, 2);
        assert_eq!(overflow.walkie_talkie_application_batch_overflow, 1);
        assert_eq!(overflow.walkie_talkie_batch_lifecycle_errors, 1);
    }

    #[test]
    fn shorter_selected_batch_finishes_its_common_chaff_suffix_before_the_next_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded_pair(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
                r#"[
                    {"outgoing": 1, "incoming": 1, "batch_end": false},
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("asymmetric batch-aware mould");
        assert_eq!(defense.source_batch_ends, [0, 1]);
        assert_eq!(defense.batch_ends, HashSet::from([1, 2]));

        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let application_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("selected component outgoing cell");
        resolve(
            &mut defense,
            1,
            application_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);

        assert!(!defense.can_start_application_batch());
        let suffix_outgoing = defense
            .next_event(Duration::from_micros(3))
            .expect("common first-batch chaff suffix");
        assert_eq!(suffix_outgoing.direction(), Direction::Outgoing);
        resolve(
            &mut defense,
            4,
            suffix_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(4))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 5);

        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(5)), None);
        assert_eq!(
            defense
                .diagnostics()
                .walkie_talkie_observed_application_batches,
            1
        );
    }

    #[test]
    fn natural_ingress_outside_an_incoming_turn_is_a_lifecycle_failure() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("moulded sequence");
        application_batch_started(&mut defense, 0);

        application_bytes(&mut defense, 1, Direction::Incoming, 37);

        let diagnostics = defense.diagnostics();
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            37
        );
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 1);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 37);
    }

    #[test]
    fn evaluation_over_source_envelope_is_diagnostic_even_when_pair_mould_is_exact() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded_pair(
                r#"[{"outgoing": 1, "incoming": 1}]"#,
                r#"[{"outgoing": 3, "incoming": 3}]"#,
            ),
        )
        .expect("asymmetric molded sequence");

        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 200);
        for at_us in 1..=3 {
            let outgoing = defense
                .next_event(Duration::from_micros(at_us))
                .expect("molded outgoing cell");
            assert_eq!(outgoing.direction(), Direction::Outgoing);
            resolve(
                &mut defense,
                at_us,
                outgoing,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        application_bytes(&mut defense, 4, Direction::Incoming, 200);
        for at_us in 4..=6 {
            let incoming = defense
                .next_event(Duration::from_micros(at_us))
                .expect("molded incoming cell");
            assert_eq!(incoming.direction(), Direction::Incoming);
            incoming_wire(&mut defense, at_us);
        }
        application_batch_completed(&mut defense, 7);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_outgoing_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_observed_outgoing_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_natural_outgoing_bytes, 200);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 200);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
    }

    #[test]
    fn completed_batch_still_waits_for_incoming_payload_budget() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");

        application_batch_started(&mut defense, 0);
        application_batch_completed(&mut defense, 1);
        assert!(!defense.can_start_application_batch());
        let outgoing = defense
            .next_event(Duration::from_micros(1))
            .expect("outgoing");
        resolve(
            &mut defense,
            2,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(2))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );

        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        assert!(!defense.can_start_application_batch());
        incoming_wire(&mut defense, 60_000_001);
        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(60_000_001)), None);
        application_batch_started(&mut defense, 60_000_002);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_002))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn malformed_application_batch_lifecycle_is_diagnostic() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("molded sequence");

        application_batch_completed(&mut defense, 0);
        application_batch_started(&mut defense, 1);
        application_batch_started(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Outgoing, 100);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);
        application_batch_completed(&mut defense, 4);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 2);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 4);
        assert!(!diagnostics.walkie_talkie_application_batch_active);
    }

    #[test]
    fn incoming_payload_satisfies_the_turn() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 1, "incoming": 0}
                ]"#,
            ),
        )
        .expect("molded sequence");
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        incoming_wire(&mut defense, 1_000);

        assert_eq!(
            defense
                .next_event(Duration::from_millis(1))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn diagnostics_preserve_each_burst_instead_of_cancelling_counts() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 0, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        assert!(defense.next_event(Duration::ZERO).is_some());
        incoming_payload(&mut defense, 1, 200, false);
        assert!(defense.next_event(Duration::from_micros(1)).is_some());

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_observed_cell_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 2);
        assert_eq!(
            diagnostics.walkie_talkie_burst_realization,
            [
                WalkieTalkieBurstDiagnostics {
                    index: 0,
                    target_outgoing_cells: 0,
                    target_incoming_cells: 1,
                    observed_outgoing_cells: 0,
                    observed_incoming_cells: 2,
                },
                WalkieTalkieBurstDiagnostics {
                    index: 1,
                    target_outgoing_cells: 0,
                    target_incoming_cells: 1,
                    observed_outgoing_cells: 0,
                    observed_incoming_cells: 0,
                },
            ]
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the controller must deliver Walkie-Talkie timestamps monotonically")]
    fn non_monotonic_timestamps_violate_the_controller_contract() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 0}]"#),
        )
        .expect("molded sequence");
        assert!(defense.next_event(Duration::from_micros(10)).is_some());
        assert!(defense.next_event(Duration::from_micros(9)).is_none());
    }

    #[test]
    fn incoming_only_suffix_keeps_chaff_stream_data_gated_until_done() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("molded sequence");

        assert!(defense.is_outgoing_complete());
        assert!(!defense.can_release_chaff_send_shaping());
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 10);
        assert_eq!(defense.next_event(Duration::from_micros(109)), None);
        assert_eq!(defense.next_event(Duration::from_micros(999)), None);
        assert!(!defense.can_release_chaff_send_shaping());
        assert_eq!(defense.next_event(Duration::from_millis(1)), None);
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            100
        );
        incoming_wire(&mut defense, 1_001);
        assert!(defense.can_release_chaff_send_shaping());
    }

    #[test]
    fn incoming_turn_requires_observed_payload_for_liveness() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        incoming_wire(&mut defense, 60_000_001);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_001))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn completion_requires_both_application_and_molded_sequence() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 0}]"#),
        )
        .expect("molded sequence");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });
        assert!(!defense.is_complete());

        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );

        assert!(defense.is_complete());
        assert!(defense.is_outgoing_complete());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic golden keeps every terminal credit and payload signal explicit"
    )]
    fn full_molded_sequence_has_a_golden_schedule() {
        let mut defense = WalkieTalkie::from_json(
            &config(100),
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("molded sequence");
        let outgoing = |at_us| {
            Packet::new(Duration::from_micros(at_us), Direction::Outgoing, 100)
                .expect("golden outgoing packet")
        };
        let incoming = |at_us| {
            Packet::new(Duration::from_micros(at_us), Direction::Incoming, 100)
                .expect("golden incoming packet")
        };
        let script = [
            (
                Duration::from_micros(10),
                SignalKind::Resolved {
                    packet: outgoing(0),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(20),
                SignalKind::Resolved {
                    packet: outgoing(0),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(30),
                SignalKind::Resolved {
                    packet: incoming(20),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(30),
                SignalKind::PayloadBytes {
                    direction: Direction::Incoming,
                    bytes: 100,
                    cover: false,
                },
            ),
            (
                Duration::from_micros(30),
                SignalKind::ReceiveCreditConsumed { bytes: 100 },
            ),
            (
                Duration::from_micros(40),
                SignalKind::Resolved {
                    packet: incoming(20),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(40),
                SignalKind::PayloadBytes {
                    direction: Direction::Incoming,
                    bytes: 100,
                    cover: false,
                },
            ),
            (
                Duration::from_micros(40),
                SignalKind::ReceiveCreditConsumed { bytes: 100 },
            ),
            (
                Duration::from_micros(50),
                SignalKind::Resolved {
                    packet: outgoing(40),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(60),
                SignalKind::Resolved {
                    packet: incoming(50),
                    outcome: EventOutcome::Satisfied { observed: 100 },
                },
            ),
            (
                Duration::from_micros(60),
                SignalKind::PayloadBytes {
                    direction: Direction::Incoming,
                    bytes: 100,
                    cover: true,
                },
            ),
            (
                Duration::from_micros(60),
                SignalKind::ReceiveCreditConsumed { bytes: 100 },
            ),
            (Duration::from_micros(60), SignalKind::ApplicationComplete),
        ];
        let actual: Vec<_> = drive(&mut defense, &script, Duration::from_micros(60))
            .into_iter()
            .map(|packet| (packet.timestamp_us(), packet.direction(), packet.length()))
            .collect();
        assert_eq!(
            actual,
            [
                (0, Direction::Outgoing, 100),
                (0, Direction::Outgoing, 100),
                (20, Direction::Incoming, 100),
                (20, Direction::Incoming, 100),
                (40, Direction::Outgoing, 100),
                (50, Direction::Incoming, 100),
            ]
        );
        assert!(defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            0
        );
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_outgoing_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_observed_outgoing_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_outgoing_shortfall_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_outgoing_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 100);
        assert_eq!(diagnostics.walkie_talkie_target_observed_cell_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_control_only_crossings, 0);
    }
}
