// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use serde::{Deserialize, Serialize};

use super::{QcsdChaffRequestId, QcsdEndpointId, QcsdSlotId, QcsdStreamId};
use crate::{MissedSlotReason, Packet, Resource};

/// Commands emitted by the controller for a Neqo endpoint adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QcsdAction {
    ConfigureManualReceive {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        initial_limit: u64,
    },
    ConfigureAutomaticReceive {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        window: u64,
    },
    IncreaseReceiveLimit {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        packet: Packet,
        slot: QcsdSlotId,
    },
    /// Grant bounded receive credit solely so HTTP/3 can classify the next
    /// request-stream frame at a pristine parser boundary.
    ///
    /// This action deliberately has no packet or slot: bytes in its raw offset
    /// range are parser-owned and can never satisfy scheduled incoming work.
    LeaseParserReceive {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        increase: u64,
    },
    SendPacket {
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
        /// Remaining monotonic time in which the adapter may satisfy this slot.
        deadline_after_us: u64,
        allow_stream_data: bool,
    },
    /// Permit chaff request bytes to leave without scheduled capacity after
    /// the outgoing schedule ends, allowing an incoming-only tail to finish.
    ReleaseChaffSendShaping {
        endpoint: QcsdEndpointId,
    },
    RequestChaff {
        endpoint: QcsdEndpointId,
        resource: Resource,
        request_id: QcsdChaffRequestId,
    },
    SlotMissed {
        endpoint: Option<QcsdEndpointId>,
        packet: Packet,
        slot: QcsdSlotId,
        reason: MissedSlotReason,
    },
    /// An incoming slot is complete after every scheduled receive-credit byte
    /// has been consumed as response STREAM data.
    SlotSatisfied {
        endpoint: Option<QcsdEndpointId>,
        packet: Packet,
        slot: QcsdSlotId,
    },
    DefenseComplete,
}
