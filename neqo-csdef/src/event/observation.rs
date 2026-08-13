// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use serde::{Deserialize, Serialize};

use super::{QcsdChaffRequestId, QcsdEndpointId, QcsdRequestRole, QcsdSlotId, QcsdStreamId};
use crate::{Direction, Packet};

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a predicate over &T"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// One per-run clock shared by all QCSD endpoints.
///
/// The timestamp preserves when an adapter produced an observation, rather
/// than when the runner happened to drain that endpoint. The sequence supplies
/// an exact total order when several observations share one clock tick.
#[derive(Clone, Debug)]
pub struct QcsdObservationClock {
    origin: Instant,
    next_sequence: Arc<AtomicU64>,
}

impl QcsdObservationClock {
    /// Start a causal observation clock at the runner's trace origin.
    #[must_use]
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            next_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Timestamp an observation at its production instant.
    #[must_use]
    pub fn record_at(
        &self,
        observation: QcsdObservation,
        produced_at: Instant,
    ) -> TimestampedQcsdObservation {
        let produced_monotonic_ns = u64::try_from(
            produced_at
                .checked_duration_since(self.origin)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        TimestampedQcsdObservation {
            observation,
            produced_monotonic_ns,
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Timestamp an observation at the actual adapter production instant.
    #[must_use]
    pub fn record(&self, observation: QcsdObservation) -> TimestampedQcsdObservation {
        #![expect(
            clippy::disallowed_methods,
            reason = "causal research evidence requires the actual monotonic production time"
        )]
        self.record_at(observation, Instant::now())
    }
}

/// A typed QCSD observation with per-run causal production metadata.
#[derive(Debug, Eq, PartialEq)]
pub struct TimestampedQcsdObservation {
    observation: QcsdObservation,
    produced_monotonic_ns: u64,
    sequence: u64,
}

/// Exact transport STREAM-frame transmission evidence for qualification.
///
/// Unlike [`QcsdObservation::StreamDataTransmitted`], this transcript includes
/// HTTP/3 and QPACK critical streams that have no application/chaff request
/// role. It is a separate drain-only evidence channel and is never delivered
/// to a defense controller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QcsdStreamTransmission {
    pub sequence: u64,
    pub stream: QcsdStreamId,
    pub role: Option<QcsdRequestRole>,
    pub offset: u64,
    pub bytes: u64,
    pub fin: bool,
    pub slot: Option<QcsdSlotId>,
}

impl TimestampedQcsdObservation {
    /// The typed observation payload.
    #[must_use]
    pub const fn observation(&self) -> &QcsdObservation {
        &self.observation
    }

    /// Nanoseconds from the runner's trace origin to observation production.
    #[must_use]
    pub const fn produced_monotonic_ns(&self) -> u64 {
        self.produced_monotonic_ns
    }

    /// Per-run total-order sequence assigned at production.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Consume the record and return its typed observation.
    #[must_use]
    pub fn into_observation(self) -> QcsdObservation {
        self.observation
    }
}

/// Why a transport adapter could not satisfy a scheduled slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedSlotReason {
    NoEndpoint,
    InsufficientIncomingCapacity,
    CongestionLimited,
    PacingLimited,
    KeysUnavailable,
    PathMtu,
    MandatoryFrames,
    EndpointClosed,
    /// Receive credit reached the wire, but the corresponding stream or
    /// endpoint ended before every scheduled offset was consumed.
    ReceiveCreditRetired,
    DeadlineExpired,
    RunAborted,
}

/// Why an otherwise valid client 1-RTT datagram could not be morphed in place.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMorphingBypassReason {
    /// Pacing permitted ACK/control transmission but not a shaped datagram.
    PacingLimited,
    /// Congestion control permitted ACK/control transmission but not a shaped datagram.
    CongestionLimited,
    /// The 1-RTT packet followed another QUIC packet in the same UDP datagram.
    Coalesced,
    /// The natural packet length could not be represented by the QCSD size domain.
    InvalidPacketSize,
    /// The validated conditional row unexpectedly produced no usable target.
    TargetSelectionFailed,
}

/// Exact outcome of the transport's same-datagram Traffic Morphing hook.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TrafficMorphingOutcome {
    Morphed { target_udp_size: u16 },
    Bypassed { reason: TrafficMorphingBypassReason },
}

/// How a response stream terminated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdStreamFinish {
    Fin,
    Reset,
    LocalError,
}

/// Causal provenance of one UDP datagram observed by a QCSD endpoint.
///
/// `DefenseCover` requires positive transport evidence: a scheduled cover
/// target, reviewed-chaff STREAM data or flow-control, or an ACK whose complete
/// acknowledged range is already classified as cover. Mixed and unknown
/// packets remain `Natural` so a defense never suppresses unproven traffic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdDatagramClass {
    Natural,
    DefenseCover,
}

/// Events reported by Neqo transport and HTTP/3 to the controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QcsdObservation {
    EndpointReady {
        endpoint: QcsdEndpointId,
        origin: String,
        max_udp_payload_size: u16,
    },
    EndpointClosed {
        endpoint: QcsdEndpointId,
    },
    StreamOpened {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        /// Best known application response body extent from the workload.
        /// Exact HTTP/3 framing is observed separately; the configured excess
        /// remains a non-advertised reservation until then.
        ///
        /// Chaff streams continue to derive their estimate from the controller's
        /// resource manifest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_response_length: Option<u64>,
    },
    /// HTTP/3 needs more bytes to finish parsing the current frame.
    HeaderProgress {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        min_remaining: u64,
        /// The parser is between response DATA frames and has not consumed
        /// any bytes of the next frame header. Controllers can combine this
        /// with a known remaining body extent to reserve the mandatory
        /// type-and-length prefix without guessing future frame contents.
        #[serde(default, skip_serializing_if = "is_false")]
        awaiting_data_frame: bool,
    },
    /// One complete HEADERS frame on a response request stream.
    ///
    /// Interim and final fields are decoded when available. Trailers are
    /// represented by `None` fields because Neqo currently ignores their
    /// header block, while `frame_bytes` still accounts for their exact raw
    /// extent once.
    ResponseHeaders {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frame_bytes: u64,
        status: Option<u16>,
        content_length: Option<u64>,
    },
    DataFrame {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frame_header_bytes: u64,
        data_bytes: u64,
    },
    /// Complete `PUSH_PROMISE` framing consumed on a request stream.
    PushPromiseFrame {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frame_bytes: u64,
    },
    /// Complete legal extension frames ignored on a request stream.
    /// Known HEADERS, DATA, and `PUSH_PROMISE` frames use their typed events and
    /// never contribute here.
    IgnoredRequestStreamFrame {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frame_bytes: u64,
    },
    /// Raw request-stream offsets consumed by HTTP/3.
    ///
    /// These include response HEADERS and frame headers, DATA bytes, trailers,
    /// and any other bytes advanced by the request-stream frame reader. They
    /// are deliberately not a body-only or server-datagram measurement.
    BytesRead {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        bytes: u64,
    },
    StreamDataBlocked {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        blocked_at: u64,
    },
    /// Confirms that an absolute receive limit was encoded on the wire.
    ReceiveLimitAdvertised {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        /// Slot whose credit was represented by this encoded limit.
        #[serde(default)]
        slot: Option<QcsdSlotId>,
    },
    StreamFinished {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        finish: QcsdStreamFinish,
    },
    ChaffRequestFailed {
        resource_id: u32,
        #[serde(default)]
        request_id: Option<QcsdChaffRequestId>,
    },
    /// A workload resource completed and may unlock dependent chaff resources.
    ResourceCompleted {
        resource_id: u32,
        success: bool,
    },
    /// The runner opened every globally ready application request in one batch.
    ApplicationBatchStarted,
    /// Every application stream belonging to the current global batch terminated.
    ApplicationBatchCompleted,
    ApplicationComplete,
    Datagram {
        endpoint: QcsdEndpointId,
        direction: Direction,
        length: u16,
        timestamp_us: u64,
    },
    /// Post-decryption/build causal classification of the same wire datagram.
    ///
    /// The runner retains the independent raw [`Self::Datagram`] observation
    /// for packet reconciliation. Reactive defenses consume this typed view so
    /// controller-induced QUIC feedback cannot recursively restart them.
    ClassifiedDatagram {
        endpoint: QcsdEndpointId,
        direction: Direction,
        length: u16,
        class: QcsdDatagramClass,
    },
    /// A natural client 1-RTT datagram was handled by the in-packet Traffic
    /// Morphing adapter.
    TrafficMorphingEgress {
        endpoint: QcsdEndpointId,
        source_udp_size: u16,
        outcome: TrafficMorphingOutcome,
    },
    /// One application or reviewed-chaff STREAM range was encoded in a
    /// client-egress packet.
    ///
    /// Offset and length make retransmissions explicit so parameter fitting
    /// can count unique STREAM bytes while runtime turn-integrity checks count
    /// every actual transmission.
    StreamDataTransmitted {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        offset: u64,
        bytes: u64,
        /// Whether this transmission carried the request-stream FIN.
        #[serde(default, skip_serializing_if = "is_false")]
        fin: bool,
        /// Scheduled packet target that owned this transmission. `None`
        /// identifies targetless request-stream output explicitly.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot: Option<QcsdSlotId>,
    },
    /// One request-stream range was acknowledged by the peer. The controller
    /// activates chaff only after these observations cover `[0, FIN)` without
    /// gaps; transmission alone is insufficient because it can be lost.
    StreamDataAcknowledged {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        offset: u64,
        bytes: u64,
        #[serde(default, skip_serializing_if = "is_false")]
        fin: bool,
    },
    SlotSatisfied {
        endpoint: QcsdEndpointId,
        slot: QcsdSlotId,
        observed_size: u16,
    },
    SlotMissed {
        endpoint: QcsdEndpointId,
        slot: QcsdSlotId,
        packet: Packet,
        reason: MissedSlotReason,
    },
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{QcsdObservation, QcsdObservationClock};

    #[test]
    fn stream_opened_without_expected_response_length_remains_compatible() {
        let json = r#"{
            "type":"stream_opened",
            "endpoint":1,
            "stream":4,
            "role":"application"
        }"#;
        let observation: QcsdObservation =
            serde_json::from_str(json).expect("legacy StreamOpened observation");
        assert!(matches!(
            observation,
            QcsdObservation::StreamOpened {
                expected_response_length: None,
                ..
            }
        ));
        let encoded = serde_json::to_value(observation).expect("serialize StreamOpened");
        assert!(encoded.get("expected_response_length").is_none());
    }

    #[test]
    fn legacy_header_progress_defaults_to_not_awaiting_a_data_frame() {
        let json = r#"{
            "type":"header_progress",
            "endpoint":1,
            "stream":4,
            "min_remaining":2
        }"#;
        let observation: QcsdObservation =
            serde_json::from_str(json).expect("legacy HeaderProgress observation");
        assert_eq!(
            observation,
            QcsdObservation::HeaderProgress {
                endpoint: super::QcsdEndpointId(1),
                stream: super::QcsdStreamId(4),
                min_remaining: 2,
                awaiting_data_frame: false,
            }
        );
        let encoded = serde_json::to_value(observation).expect("serialize HeaderProgress");
        assert!(encoded.get("awaiting_data_frame").is_none());
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the clock contract test needs one local monotonic origin"
    )]
    fn shared_observation_clock_preserves_cross_endpoint_production_order() {
        let origin = Instant::now();
        let clock = QcsdObservationClock::new(origin);
        let other_endpoint = clock.clone();

        let first = clock.record_at(
            QcsdObservation::ApplicationBatchStarted,
            origin + Duration::from_nanos(10),
        );
        let second = other_endpoint.record_at(
            QcsdObservation::ApplicationComplete,
            origin + Duration::from_nanos(11),
        );
        let third = clock.record_at(
            QcsdObservation::ApplicationBatchCompleted,
            origin + Duration::from_nanos(11),
        );

        assert_eq!(
            [first.sequence(), second.sequence(), third.sequence(),],
            [0, 1, 2]
        );
        assert_eq!(
            [
                first.produced_monotonic_ns(),
                second.produced_monotonic_ns(),
                third.produced_monotonic_ns(),
            ],
            [10, 11, 11]
        );
    }
}
