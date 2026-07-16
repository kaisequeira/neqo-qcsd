// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use test_fixture::now;

use super::{connect_force_idle, default_client, default_server};
use crate::Error;

#[test]
fn exact_packet_targets_produce_one_udp_datagram_each() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    for target in [900_u16, 1_000, 1_200] {
        client.qcsd_queue_packet_target(target).unwrap();
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
        client.qcsd_queue_packet_target(63),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        client.qcsd_queue_packet_target(u16::MAX),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn packet_target_never_shapes_handshake_output() {
    let mut client = default_client();
    assert_eq!(
        client.qcsd_queue_packet_target(1_200),
        Err(Error::NotAvailable)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}
