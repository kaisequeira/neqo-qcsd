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

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a predicate over &T"
)]
const fn is_exact_send_policy(value: &QcsdSendPolicy) -> bool {
    matches!(value, QcsdSendPolicy::Exact)
}

/// Transport policy for one scheduled client-egress attempt.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdSendPolicy {
    /// Preserve the existing exact-size, deadline-window behavior.
    #[default]
    Exact,
    /// Attempt once at release and expose congestion-limited partial/suppressed outcomes.
    CongestionSensitive,
}

/// Client-local reason for terminating an unfinished reviewed-chaff request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdChaffCancellationReason {
    /// CS-BuFLO's local early-termination adaptation reached its stop state.
    #[default]
    CsBufloLocalEarlyTermination,
    /// `BuFLO` drained every whole cell and only an ineligible sub-cell tail remained.
    BufloTerminalSubcellTail,
}

/// Why a future packet preview was retracted before becoming a defense event.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdPrearmCancellationReason {
    /// A fresh terminal snapshot closed the defense before the preview's release.
    #[default]
    DefenseTerminal,
    /// The enclosing run ended before the preview could become scheduled work.
    RunAborted,
}

/// Result of checking or applying one QCSD receive-limit action.
///
/// Lifecycle outcomes are non-fatal: a controller can cancel the stream's
/// unadvertised suffix without treating an ordinary FIN or stream cleanup as
/// a transport failure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdReceiveLimitOutcome {
    /// The action is valid for a live receiving stream.
    Applied,
    /// A final size is known, so further receive credit cannot be useful.
    FinalKnown,
    /// The receive side reached a terminal state but is still retained.
    Terminal,
    /// The transport no longer retains the stream.
    Gone,
}

/// Fatal class of a rejected QCSD receive-limit action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdReceiveLimitFatal {
    /// The requested limit is below bytes already advertised or consumed.
    WouldRevoke,
    /// The action does not strictly advance the pending manual limit.
    Order,
    /// Action metadata disagrees with the transport or controller ledger.
    Ledger,
}

/// Evidence for a fatal receive-limit preflight or apply rejection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QcsdReceiveLimitError {
    /// Stable fatal classification used by runner traces and policy.
    pub kind: QcsdReceiveLimitFatal,
    /// Absolute limit requested by the rejected action or range boundary.
    pub requested_limit: u64,
    /// Transport/controller high-water mark that rejected the request.
    pub reference_limit: u64,
}

impl std::fmt::Display for QcsdReceiveLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QCSD receive-limit {:?}: requested {}, reference {}",
            self.kind, self.requested_limit, self.reference_limit
        )
    }
}

impl std::error::Error for QcsdReceiveLimitError {}

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

/// Transport-independent identity of one receive-limit action.
///
/// The runner adds the drained-batch index when matching a cancellation. This
/// identity deliberately is not serialized into [`QcsdAction`], preserving the
/// established action JSON and trace schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QcsdReceiveActionIdentity {
    /// Scheduled receive credit owned directly by one logical slot.
    Scheduled {
        /// Endpoint adapter receiving the action.
        endpoint: QcsdEndpointId,
        /// QUIC receive stream whose limit advances.
        stream: QcsdStreamId,
        /// New absolute `MAX_STREAM_DATA` limit.
        absolute_limit: u64,
        /// Logical schedule slot owning this credit.
        slot: QcsdSlotId,
    },
    /// Parser-liveness lease, optionally backed by a scheduled slot.
    ParserLease {
        /// Endpoint adapter receiving the action.
        endpoint: QcsdEndpointId,
        /// QUIC receive stream whose limit advances.
        stream: QcsdStreamId,
        /// New absolute `MAX_STREAM_DATA` limit.
        absolute_limit: u64,
        /// Exact contiguous lease length.
        increase: u64,
        /// Optional schedule ownership for consumed lease bytes.
        owner: Option<QcsdParserLeaseOwner>,
    },
}

impl QcsdReceiveActionIdentity {
    /// Endpoint component of this internal identity.
    #[must_use]
    pub const fn endpoint(self) -> QcsdEndpointId {
        match self {
            Self::Scheduled { endpoint, .. } | Self::ParserLease { endpoint, .. } => endpoint,
        }
    }

    /// Stream component of this internal identity.
    #[must_use]
    pub const fn stream(self) -> QcsdStreamId {
        match self {
            Self::Scheduled { stream, .. } | Self::ParserLease { stream, .. } => stream,
        }
    }

    /// Absolute receive limit component of this internal identity.
    #[must_use]
    pub const fn absolute_limit(self) -> u64 {
        match self {
            Self::Scheduled { absolute_limit, .. } | Self::ParserLease { absolute_limit, .. } => {
                absolute_limit
            }
        }
    }

    /// Scheduled owner, if this action carries one.
    #[must_use]
    pub const fn slot(self) -> Option<QcsdSlotId> {
        match self {
            Self::Scheduled { slot, .. } => Some(slot),
            Self::ParserLease { owner, .. } => match owner {
                Some(owner) => Some(owner.slot),
                None => None,
            },
        }
    }
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
        /// Adapter realization policy. Omitted legacy actions remain exact.
        #[serde(default, skip_serializing_if = "is_exact_send_policy")]
        send_policy: QcsdSendPolicy,
    },
    /// Stage one retractable future packet target without emitting a defense
    /// event. It must be committed or canceled before transport is driven at
    /// the target's release.
    PrearmPacket {
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
        not_before_after_us: u64,
        deadline_after_us: u64,
        allow_stream_data: bool,
    },
    /// Promote a staged target to a real defense event. Transport already owns
    /// the target; this action binds controller and trace accounting only.
    CommitPrearmedPacket {
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
    },
    /// Retract a staged target which never became a defense event.
    CancelPrearmedPacket {
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
        reason: QcsdPrearmCancellationReason,
    },
    /// Permit chaff request bytes to leave without scheduled capacity after
    /// the outgoing schedule ends, allowing an incoming-only tail to finish.
    ReleaseChaffSendShaping {
        endpoint: QcsdEndpointId,
    },
    /// Restore ordinary application request transmission after CS-BuFLO's
    /// client-local early-termination boundary. Chaff remains shaped and is
    /// canceled separately; this is never a bilateral completion signal.
    ReleaseApplicationSendShaping {
        endpoint: QcsdEndpointId,
    },
    RequestChaff {
        endpoint: QcsdEndpointId,
        resource: Resource,
        request_id: QcsdChaffRequestId,
    },
    /// Cancel one still-open reviewed-chaff request at a typed client-local
    /// terminal boundary. This is standard HTTP/3 cancellation, never a
    /// bilateral padding-complete signal.
    CancelChaff {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        /// Auditable candidate-defense reason. Older schema-two actions
        /// without this field deserialize as CS-BuFLO local termination.
        #[serde(default)]
        reason: QcsdChaffCancellationReason,
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

impl QcsdAction {
    /// Stable internal identity used to reconcile preflight cancellation with
    /// the exact actions already drained by the runner.
    #[must_use]
    pub const fn receive_identity(&self) -> Option<QcsdReceiveActionIdentity> {
        match self {
            Self::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                slot,
                ..
            } => Some(QcsdReceiveActionIdentity::Scheduled {
                endpoint: *endpoint,
                stream: *stream,
                absolute_limit: *absolute_limit,
                slot: *slot,
            }),
            Self::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit,
                increase,
                owner,
            } => Some(QcsdReceiveActionIdentity::ParserLease {
                endpoint: *endpoint,
                stream: *stream,
                absolute_limit: *absolute_limit,
                increase: *increase,
                owner: *owner,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::Value;

    use super::{
        QcsdAction, QcsdChaffCancellationReason, QcsdParserLeaseOwner,
        QcsdPrearmCancellationReason, QcsdReceiveActionIdentity, QcsdSendPolicy,
    };
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
            send_policy: QcsdSendPolicy::Exact,
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
            send_policy: QcsdSendPolicy::Exact,
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

    #[test]
    fn rolling_prearm_lifecycle_actions_round_trip_with_typed_cancellation() {
        let endpoint = QcsdEndpointId(2);
        let packet =
            Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_200).expect("packet");
        let slot = QcsdSlotId(19);
        let actions = [
            QcsdAction::PrearmPacket {
                endpoint,
                packet,
                slot,
                not_before_after_us: 9,
                deadline_after_us: 5_009,
                allow_stream_data: true,
            },
            QcsdAction::CommitPrearmedPacket {
                endpoint,
                packet,
                slot,
            },
            QcsdAction::CancelPrearmedPacket {
                endpoint,
                packet,
                slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            },
        ];

        for action in &actions {
            let encoded = serde_json::to_value(action).expect("serialize prearm action");
            assert_eq!(
                serde_json::from_value::<QcsdAction>(encoded).expect("deserialize prearm action"),
                action.clone()
            );
        }
        let cancellation =
            serde_json::to_value(actions[2].clone()).expect("serialize cancellation");
        assert_eq!(
            cancellation.get("reason").and_then(Value::as_str),
            Some("run_aborted")
        );
    }

    #[test]
    fn cancel_chaff_reason_is_typed_and_legacy_actions_default_to_cs_buflo() {
        let buflo = QcsdAction::CancelChaff {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
        };
        let buflo_json = serde_json::to_value(&buflo).expect("serialize typed cancellation");
        assert_eq!(
            buflo_json.get("reason").and_then(Value::as_str),
            Some("buflo_terminal_subcell_tail")
        );
        assert_eq!(
            serde_json::from_value::<QcsdAction>(buflo_json)
                .expect("deserialize typed cancellation"),
            buflo
        );

        let legacy_json = serde_json::json!({
            "type": "cancel_chaff",
            "endpoint": 1,
            "stream": 4,
        });
        assert_eq!(
            serde_json::from_value::<QcsdAction>(legacy_json)
                .expect("deserialize legacy cancellation"),
            QcsdAction::CancelChaff {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
            }
        );
    }

    #[test]
    fn application_send_release_is_typed_and_round_trips() {
        let action = QcsdAction::ReleaseApplicationSendShaping {
            endpoint: QcsdEndpointId(7),
        };
        let encoded = serde_json::to_value(&action).expect("serialize application release");
        assert_eq!(
            encoded.get("type").and_then(Value::as_str),
            Some("release_application_send_shaping")
        );
        assert_eq!(
            serde_json::from_value::<QcsdAction>(encoded).expect("deserialize application release"),
            action
        );
    }

    #[test]
    fn receive_action_identity_is_internal_and_unambiguous() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("incoming packet");
        let owner = QcsdParserLeaseOwner {
            packet,
            slot: QcsdSlotId(9),
        };
        let scheduled = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            absolute_limit: 26,
            packet,
            slot: QcsdSlotId(8),
        };
        assert_eq!(
            scheduled.receive_identity(),
            Some(QcsdReceiveActionIdentity::Scheduled {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                absolute_limit: 26,
                slot: QcsdSlotId(8),
            })
        );
        let parser = QcsdAction::LeaseParserReceive {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            absolute_limit: 29,
            increase: 3,
            owner: Some(owner),
        };
        assert_eq!(
            parser.receive_identity(),
            Some(QcsdReceiveActionIdentity::ParserLease {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                absolute_limit: 29,
                increase: 3,
                owner: Some(owner),
            })
        );
        let json = serde_json::to_value(parser).expect("serialize parser action");
        assert!(json.get("receive_identity").is_none());
    }
}
