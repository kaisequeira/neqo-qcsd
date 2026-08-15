// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use serde::{Deserialize, Serialize};

use super::{QcsdChaffRequestId, QcsdEndpointId, QcsdSlotId, QcsdStreamId};
use crate::{MissedSlotReason, Packet, Resource};

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a predicate over &T"
)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Logical scheduled-slot ownership carried by a parser receive lease.
///
/// The transport action remains slotless: this metadata lets the runner trace
/// when an already-owned scheduled slot was first exposed to the adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QcsdParserLeaseOwner {
    /// Scheduled packet whose raw receive bytes own the lease.
    pub packet: Packet,
    /// Logical scheduled slot to trace from lease issuance to terminal state.
    pub slot: QcsdSlotId,
}

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
    /// The transport limit itself has no slot. `owner` is trace/accounting
    /// metadata only and is present when the controller reserved this lease
    /// for an existing scheduled slot. Granting or advertising the lease never
    /// satisfies that slot; only consumed overlap can do so.
    LeaseParserReceive {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        increase: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<QcsdParserLeaseOwner>,
    },
    SendPacket {
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
        /// Remaining monotonic time before this slot may affect transport output.
        #[serde(default, skip_serializing_if = "is_zero")]
        not_before_after_us: u64,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::Value;

    use super::{QcsdAction, QcsdParserLeaseOwner};
    use crate::{Direction, Packet, QcsdEndpointId, QcsdSlotId, QcsdStreamId};

    #[test]
    fn parser_lease_owner_is_optional_and_round_trips() {
        let unowned = QcsdAction::LeaseParserReceive {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            absolute_limit: 17,
            increase: 16,
            owner: None,
        };
        let unowned_json = serde_json::to_value(&unowned).expect("serialize unowned lease");
        assert_eq!(unowned_json.get("owner"), None);
        assert_eq!(
            serde_json::from_value::<QcsdAction>(unowned_json).expect("deserialize unowned lease"),
            unowned
        );

        let lease_owner = QcsdParserLeaseOwner {
            packet: Packet::new(Duration::from_micros(3), Direction::Incoming, 10).expect("packet"),
            slot: QcsdSlotId(9),
        };
        let scheduled_lease = QcsdAction::LeaseParserReceive {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            absolute_limit: 27,
            increase: 10,
            owner: Some(lease_owner),
        };
        let owned_json = serde_json::to_value(&scheduled_lease).expect("serialize owned lease");
        assert!(matches!(owned_json.get("owner"), Some(Value::Object(_))));
        assert_eq!(
            serde_json::from_value::<QcsdAction>(owned_json).expect("deserialize owned lease"),
            scheduled_lease
        );
    }

    #[test]
    fn send_packet_not_before_defaults_to_zero_and_zero_is_omitted() {
        let packet =
            Packet::new(Duration::from_micros(7), Direction::Outgoing, 1_200).expect("packet");
        let immediate = QcsdAction::SendPacket {
            endpoint: QcsdEndpointId(1),
            packet,
            slot: QcsdSlotId(3),
            not_before_after_us: 0,
            deadline_after_us: 5_000,
            allow_stream_data: false,
        };
        let immediate_json = serde_json::to_value(&immediate).expect("serialize send action");
        assert_eq!(immediate_json.get("not_before_after_us"), None);
        assert_eq!(
            serde_json::from_value::<QcsdAction>(immediate_json)
                .expect("deserialize legacy-shaped send action"),
            immediate
        );

        let staged = QcsdAction::SendPacket {
            endpoint: QcsdEndpointId(1),
            packet,
            slot: QcsdSlotId(3),
            not_before_after_us: 17,
            deadline_after_us: 5_000,
            allow_stream_data: false,
        };
        let staged_json = serde_json::to_value(&staged).expect("serialize staged send action");
        assert_eq!(
            staged_json
                .get("not_before_after_us")
                .and_then(Value::as_u64),
            Some(17)
        );
        assert_eq!(
            serde_json::from_value::<QcsdAction>(staged_json)
                .expect("deserialize staged send action"),
            staged
        );
    }
}
