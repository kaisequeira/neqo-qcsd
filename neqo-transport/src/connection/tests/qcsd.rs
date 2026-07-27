// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use neqo_csdef::{
    Direction, MissedSlotReason, Packet, QcsdEndpointId, QcsdObservation, QcsdRequestRole,
    QcsdSlotId,
};
use test_fixture::now;

use super::{
    AT_LEAST_PTO, DEFAULT_RTT, connect_force_idle, connect_rtt_idle, cwnd_avail, default_client,
    default_server, fill_cwnd, fill_stream,
};
use crate::{
    Connection, Error, StreamType, connection::params::INITIAL_LOCAL_MAX_STREAM_DATA,
    sender::PACING_BURST_SIZE,
};

fn queue_target(
    connection: &mut Connection,
    slot: u64,
    size: u16,
    allow_stream_data: bool,
) -> Result<(), Error> {
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, size).unwrap();
    connection.qcsd_queue_scheduled_packet_target(
        QcsdSlotId(slot),
        packet,
        now() + Duration::from_secs(1),
        allow_stream_data,
    )
}

#[test]
fn exact_packet_targets_produce_one_udp_datagram_each() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    for (slot, target) in [900_u16, 1_000, 1_200].into_iter().enumerate() {
        queue_target(&mut client, slot as u64, target, false).unwrap();
        assert_eq!(client.qcsd_pending_packet_targets(), 1);
        let datagram = client.process_output(now()).dgram().unwrap();
        assert_eq!(datagram.len(), usize::from(target));
        assert_eq!(client.qcsd_pending_packet_targets(), 0);
        server.process_input(datagram, now());
        _ = server.process_output(now());
    }
}

#[test]
fn packet_target_rejects_unsafe_sizes() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    assert_eq!(
        queue_target(&mut client, 1, 63, false),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        queue_target(&mut client, 2, u16::MAX, false),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn packet_target_never_shapes_handshake_output() {
    let mut client = default_client();
    assert_eq!(
        queue_target(&mut client, 1, 1_200, false),
        Err(Error::NotAvailable)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn target_uses_safe_partial_congestion_window_capacity() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    queue_target(&mut client, 1, 300, false).unwrap();
    assert_eq!(client.process_output(now()).dgram().unwrap().len(), 300);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    let mut send_time = now();
    while cwnd_avail(&client) > client.plpmtu() {
        match client.process_output(send_time) {
            crate::Output::Datagram(datagram) => assert_eq!(datagram.len(), client.plpmtu()),
            crate::Output::Callback(delay) => send_time += delay,
            crate::Output::None => panic!("stream data should fill the remaining window"),
        }
    }
    let partial = u16::try_from(cwnd_avail(&client)).unwrap();
    assert!((64..u16::try_from(client.plpmtu()).unwrap()).contains(&partial));

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, partial).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(2),
            packet,
            send_time + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(
        client.process_output(send_time).dgram().unwrap().len(),
        usize::from(partial)
    );
}

#[test]
fn attributed_target_reports_exact_satisfaction() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(11),
            packet,
            now() + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(client.process_output(now()).dgram().unwrap().len(), 1_000);
    assert!(
        client
            .qcsd_observations()
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    endpoint: QcsdEndpointId(7),
                    slot: QcsdSlotId(11),
                    observed_size: 1_000,
                }
            ))
    );
}

#[test]
fn expired_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(12), packet, now(), false)
        .unwrap();
    _ = client.process_output(now());
    assert!(
        client
            .qcsd_observations()
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(12),
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                }
            ))
    );
}

#[test]
fn congestion_limited_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let (_dropped, exhausted_at) = fill_cwnd(&mut client, stream, now());
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(14), packet, exhausted_at, false)
        .unwrap();
    _ = client.process_output(exhausted_at);
    assert!(
        client
            .qcsd_observations()
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(14),
                    reason: MissedSlotReason::CongestionLimited,
                    ..
                }
            ))
    );
}

#[test]
fn pacing_limited_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    for _ in 0..=PACING_BURST_SIZE {
        assert!(client.process_output(now).dgram().is_some());
    }
    assert!(!client.process_output(now).callback().is_zero());

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(15), packet, now, false)
        .unwrap();
    _ = client.process_output(now);
    assert!(
        client
            .qcsd_observations()
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(15),
                    reason: MissedSlotReason::PacingLimited,
                    ..
                }
            ))
    );
}

#[test]
fn closing_endpoint_misses_every_pending_target() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    for slot in [20, 21] {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
        client
            .qcsd_queue_scheduled_packet_target(
                QcsdSlotId(slot),
                packet,
                now() + Duration::from_secs(1),
                false,
            )
            .unwrap();
    }
    client.close(now(), 0, "test close");
    let misses = client
        .qcsd_observations()
        .into_iter()
        .filter(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotMissed {
                    reason: MissedSlotReason::EndpointClosed,
                    ..
                }
            )
        })
        .count();
    assert_eq!(misses, 2);
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn manual_receive_credit_is_reported_only_after_encoding() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let limit = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap() + 100;
    let slot = QcsdSlotId(99);
    client
        .qcsd_set_stream_receive_limit_for_slot(stream, limit, slot)
        .unwrap();
    assert!(client.qcsd_observations().is_empty());
    _ = client.process_output(now()).dgram().unwrap();
    assert!(
        client
            .qcsd_observations()
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::ReceiveLimitAdvertised {
                    stream: observed_stream,
                    absolute_limit,
                    slot: Some(observed_slot),
                    ..
                } if observed_stream.0 == stream.as_u64()
                    && *absolute_limit == limit
                    && *observed_slot == slot
            ))
    );
}

#[test]
fn shaped_slot_sends_application_before_chaff() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(chaff, &[0xCC; 1_000]).unwrap();
    client.stream_send(application, &[0xAA; 1_000]).unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 120).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(13),
            packet,
            now() + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let mut buffer = [0; 1_024];
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert!(read > 0);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, _)) = server.stream_recv(chaff, &mut buffer) {
        assert_eq!(read, 0);
    }
}

#[test]
fn chaff_only_target_does_not_consume_application_stream_data() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 400]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();

    queue_target(&mut client, 40, 900, false).unwrap();
    let cover = client.process_output(now()).dgram().unwrap();
    assert_eq!(cover.len(), 900);
    server.process_input(cover, now());
    let mut buffer = [0; 512];
    assert!(server.stream_recv(application, &mut buffer).is_err());

    let application_datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(application_datagram, now());
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 400);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
}

#[test]
fn chaff_can_finish_after_outgoing_shaping_is_released() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(chaff, &[0xCC; 400]).unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();
    assert!(client.process_output(now()).dgram().is_none());

    client.qcsd_release_chaff_send_shaping();
    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let mut buffer = [0; 512];
    let (read, _) = server.stream_recv(chaff, &mut buffer).unwrap();
    assert_eq!(read, 400);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
}

#[test]
fn lost_application_data_waits_for_a_later_shaped_slot() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 1_000]).unwrap();
    client.stream_send(chaff, &[0xCC; 1_000]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(30),
            packet,
            now() + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let dropped = client.process_output(now()).dgram().unwrap();
    assert_eq!(dropped.len(), 1_200);

    let recovery_time = now() + AT_LEAST_PTO;
    _ = client.process_output(recovery_time);
    let mut buffer = [0; 1_024];
    assert!(server.stream_recv(application, &mut buffer).is_err());

    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(31),
            packet,
            recovery_time + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let retransmission = client.process_output(recovery_time).dgram().unwrap();
    assert_eq!(retransmission.len(), 1_200);
    server.process_input(retransmission, recovery_time);
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 1_000);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, _)) = server.stream_recv(chaff, &mut buffer) {
        assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
    }
}
