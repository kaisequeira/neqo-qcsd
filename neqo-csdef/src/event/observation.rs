// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use serde::{Deserialize, Serialize};

use super::{QcsdChaffRequestId, QcsdEndpointId, QcsdRequestRole, QcsdSlotId, QcsdStreamId};
use crate::{Direction, Packet};

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
    DeadlineExpired,
}

/// How a response stream terminated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdStreamFinish {
    Fin,
    Reset,
    LocalError,
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
    },
    /// HTTP/3 needs more bytes to finish parsing the current frame.
    HeaderProgress {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        min_remaining: u64,
    },
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
    ApplicationComplete,
    Datagram {
        endpoint: QcsdEndpointId,
        direction: Direction,
        length: u16,
        timestamp_us: u64,
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
