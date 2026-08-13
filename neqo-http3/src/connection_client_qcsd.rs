// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

//! Narrow, feature-gated adapter between HTTP/3 and the transport-independent
//! QCSD controller.

use std::time::{Duration, Instant};

use neqo_common::Header;
use neqo_csdef::{
    QcsdAction, QcsdChaffRequestId, QcsdEndpointId, QcsdObservation, QcsdObservationClock,
    QcsdRequestRole, QcsdStreamId, Resource, TimestampedQcsdObservation, TrafficMorphingEgress,
    sanitize_chaff_headers,
};
use neqo_transport::StreamId;

use super::Http3Client;
use crate::{Error, Priority, Res, connection::RequestDescription};

impl Http3Client {
    /// Drive HTTP/3/QPACK send handlers into transport without constructing a
    /// QUIC datagram. The prefix qualifier uses this while send shaping is
    /// active to establish an exact post-SETTINGS transcript cutoff.
    pub fn qcsd_prepare_stream_output(&mut self, now: Instant) {
        self.process_http3(now);
    }

    /// Whether the peer's live HTTP/3 SETTINGS frame has been parsed.
    #[must_use]
    pub const fn qcsd_peer_settings_received(&self) -> bool {
        self.base_handler.qcsd_peer_settings_received()
    }

    /// Whether HTTP/3/QPACK or transport retains pending STREAM output.
    pub fn qcsd_has_pending_stream_send(&mut self) -> bool {
        self.base_handler.qcsd_has_pending_stream_send() || self.conn.qcsd_has_pending_stream_send()
    }

    /// Whether HTTP/3/QPACK or transport retains pending STREAM output other
    /// than the explicitly allowed request streams.
    pub fn qcsd_has_pending_stream_send_excluding(&mut self, allowed: &[StreamId]) -> bool {
        self.base_handler
            .qcsd_has_pending_stream_send_excluding(allowed)
            || self.conn.qcsd_has_pending_stream_send_excluding(allowed)
    }

    /// Exact bytes written to an HTTP/3 request stream by the production
    /// encoder, including HTTP/3 HEADERS framing and its QPACK header block.
    /// Bidirectional request streams have no stream-type prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when `stream_id` is not an active send stream.
    pub fn qcsd_request_stream_bytes(&self, stream_id: StreamId) -> Res<u64> {
        let encoded = self.base_handler.qcsd_encoded_request_bytes(stream_id)?;
        let transport = self.conn.send_stream_stats(stream_id)?.bytes_written();
        Ok(encoded.saturating_add(transport))
    }

    /// Open a same-origin nonblocking-QPACK request for qualification without
    /// installing shaped transport stream roles.
    ///
    /// # Errors
    ///
    /// Returns an error for a cross-origin target or request creation failure.
    pub fn qcsd_fetch_nonblocking(
        &mut self,
        now: Instant,
        target: &http::Uri,
        headers: &[Header],
    ) -> Res<StreamId> {
        let origin = self.qcsd_origin.as_ref().ok_or(Error::InvalidInput)?;
        if !same_origin(target, origin) {
            return Err(Error::InvalidInput);
        }
        self.base_handler.request_nonblocking(
            &mut self.conn,
            Box::new(self.events.clone()),
            Box::new(self.events.clone()),
            Some(std::rc::Rc::clone(&self.push_handler)),
            &RequestDescription {
                method: "GET",
                connect_type: None,
                target,
                headers,
                priority: Priority::default(),
            },
            now,
        )
    }

    /// Enable the narrow QCSD adapter for this HTTP/3 connection.
    ///
    /// `origin` is retained to enforce that controller-generated chaff stays on the
    /// same HTTPS origin. The caller must set the connection's initial local
    /// bidirectional stream-data limit before construction when a defense requires
    /// the published 16-byte starting allowance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] unless `origin` is an absolute HTTPS URI.
    pub fn enable_qcsd(
        &mut self,
        endpoint: QcsdEndpointId,
        origin: &http::Uri,
        configured_max_udp_payload_size: u16,
        shape_stream_sends: bool,
        keep_alive_lead_time: Duration,
    ) -> Res<()> {
        #![expect(
            clippy::disallowed_methods,
            reason = "standalone adapter callers need a monotonic observation-clock origin"
        )]
        self.enable_qcsd_with_observation_clock(
            endpoint,
            origin,
            configured_max_udp_payload_size,
            shape_stream_sends,
            keep_alive_lead_time,
            QcsdObservationClock::new(Instant::now()),
        )
    }

    /// Enable QCSD with a production clock shared by every origin in one run.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] unless `origin` is an absolute HTTPS URI.
    pub fn enable_qcsd_with_observation_clock(
        &mut self,
        endpoint: QcsdEndpointId,
        origin: &http::Uri,
        configured_max_udp_payload_size: u16,
        shape_stream_sends: bool,
        keep_alive_lead_time: Duration,
        observation_clock: QcsdObservationClock,
    ) -> Res<()> {
        let scheme = origin.scheme_str().ok_or(Error::InvalidInput)?;
        let authority = origin.authority().ok_or(Error::InvalidInput)?.as_str();
        if scheme != "https" {
            return Err(Error::InvalidInput);
        }
        self.qcsd_endpoint = Some(endpoint);
        self.qcsd_origin = Some((scheme.to_owned(), authority.to_owned()));
        self.events.qcsd_enable(endpoint, observation_clock.clone());
        let qcsd_origin = format!("{scheme}://{authority}");
        let max_udp_payload_size = self
            .conn
            .qcsd_max_udp_payload_size()
            .map_or(configured_max_udp_payload_size, |path_limit| {
                path_limit.min(configured_max_udp_payload_size)
            });
        self.events
            .qcsd_observe(|endpoint| QcsdObservation::EndpointReady {
                endpoint,
                origin: qcsd_origin,
                max_udp_payload_size,
            });
        self.conn.qcsd_enable_with_observation_clock(
            endpoint,
            shape_stream_sends,
            observation_clock,
        );
        self.conn
            .qcsd_set_udp_payload_ceiling(configured_max_udp_payload_size)?;
        self.conn
            .qcsd_set_keep_alive_lead_time(keep_alive_lead_time);
        Ok(())
    }

    /// Install the per-connection in-packet Traffic Morphing sampler.
    pub fn enable_qcsd_traffic_morphing(&mut self, morpher: TrafficMorphingEgress) {
        self.conn.qcsd_enable_traffic_morphing(morpher);
    }

    /// Register the application/chaff role of a request stream with QCSD.
    ///
    /// `expected_response_length` supplies an optional workload-derived
    /// receive-capacity floor for application streams. Chaff callers pass
    /// `None`; the controller retains ownership of their resource estimate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] when QCSD has not been enabled.
    pub fn register_qcsd_stream(
        &mut self,
        stream_id: StreamId,
        role: QcsdRequestRole,
        expected_response_length: Option<u64>,
    ) -> Res<()> {
        let endpoint = self.qcsd_endpoint.ok_or(Error::InvalidInput)?;
        self.conn.qcsd_register_stream_role(stream_id, role)?;
        self.events.qcsd_observe(|_| QcsdObservation::StreamOpened {
            endpoint,
            stream: QcsdStreamId(stream_id.as_u64()),
            role,
            expected_response_length,
        });
        Ok(())
    }

    /// Drain all adapter observations in causal production order.
    #[must_use]
    pub fn qcsd_timestamped_observations(&mut self) -> Vec<TimestampedQcsdObservation> {
        let mut observations = self.events.qcsd_timestamped_observations();
        observations.extend(self.conn.qcsd_timestamped_observations());
        observations.sort_by_key(TimestampedQcsdObservation::sequence);
        observations
    }

    /// Drain exact transport STREAM-frame evidence for qualification.
    #[must_use]
    pub fn qcsd_stream_transmissions(&mut self) -> Vec<neqo_csdef::QcsdStreamTransmission> {
        self.conn.qcsd_stream_transmissions()
    }

    /// Enable qualifier-only all-STREAM transport evidence.
    pub fn qcsd_enable_stream_transcript(&mut self, enabled: bool) {
        self.conn.qcsd_enable_stream_transcript(enabled);
    }

    /// Toggle request/critical STREAM output gating for qualification phases.
    pub const fn qcsd_enable_send_shaping(&mut self, enabled: bool) {
        self.conn.qcsd_enable_send_shaping(enabled);
    }

    /// Number of scheduled QCSD output targets not yet transmitted.
    #[must_use]
    pub fn qcsd_pending_packet_targets(&self) -> usize {
        self.conn.qcsd_pending_packet_targets()
    }

    /// Apply one controller action addressed to this connection.
    ///
    /// A newly opened chaff stream is returned so the research runner can track
    /// response status, bytes, and hashes in the same way as application streams.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid stream/packet target, cross-origin chaff,
    /// or a request that cannot be created.
    pub fn apply_qcsd_action(&mut self, now: Instant, action: QcsdAction) -> Res<Option<StreamId>> {
        let own_endpoint = self.qcsd_endpoint.ok_or(Error::InvalidInput)?;
        match action {
            QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit,
            } if endpoint == own_endpoint => {
                let stream_id = StreamId::new(stream.0);
                self.conn
                    .qcsd_set_stream_receive_limit(stream_id, initial_limit)?;
                self.conn.stream_keep_alive(stream_id, true)?;
            }
            QcsdAction::ConfigureAutomaticReceive {
                endpoint,
                stream,
                window,
            } if endpoint == own_endpoint => {
                self.conn
                    .qcsd_set_stream_auto_receive(StreamId::new(stream.0), window)?;
            }
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                slot,
                ..
            } if endpoint == own_endpoint => {
                self.conn.qcsd_set_stream_receive_limit_for_slot(
                    StreamId::new(stream.0),
                    absolute_limit,
                    slot,
                )?;
            }
            QcsdAction::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit,
                ..
            } if endpoint == own_endpoint => {
                self.conn
                    .qcsd_set_stream_receive_limit(StreamId::new(stream.0), absolute_limit)?;
            }
            QcsdAction::SendPacket {
                endpoint,
                packet,
                slot,
                deadline_after_us,
                allow_stream_data,
                ..
            } if endpoint == own_endpoint => {
                self.conn.qcsd_queue_scheduled_packet_target(
                    slot,
                    packet,
                    now + Duration::from_micros(deadline_after_us),
                    allow_stream_data,
                )?;
            }
            QcsdAction::ReleaseChaffSendShaping { endpoint } if endpoint == own_endpoint => {
                self.conn.qcsd_release_chaff_send_shaping();
            }
            QcsdAction::RequestChaff {
                endpoint,
                resource,
                request_id,
            } if endpoint == own_endpoint => {
                let stream_id = self.apply_qcsd_chaff_request(now, resource, request_id)?;
                return Ok(Some(stream_id));
            }
            QcsdAction::SlotMissed { .. }
            | QcsdAction::SlotSatisfied { .. }
            | QcsdAction::DefenseComplete => {}
            _ => return Ok(None),
        }
        Ok(None)
    }

    fn apply_qcsd_chaff_request(
        &mut self,
        now: Instant,
        resource: Resource,
        request_id: QcsdChaffRequestId,
    ) -> Res<StreamId> {
        let target = resource
            .url
            .parse::<http::Uri>()
            .map_err(|_| Error::InvalidInput)?;
        let origin = self.qcsd_origin.as_ref().ok_or(Error::InvalidInput)?;
        if !same_origin(&target, origin) {
            self.events
                .qcsd_observe(|_| QcsdObservation::ChaffRequestFailed {
                    resource_id: resource.id,
                    request_id: Some(request_id),
                });
            return Err(Error::InvalidInput);
        }
        let headers = strict_chaff_headers(resource.headers);
        let resource_id = resource.id;
        let stream_id = match self.base_handler.request_nonblocking(
            &mut self.conn,
            Box::new(self.events.clone()),
            Box::new(self.events.clone()),
            Some(std::rc::Rc::clone(&self.push_handler)),
            &RequestDescription {
                method: "GET",
                connect_type: None,
                target: &target,
                headers: &headers,
                priority: Priority::default(),
            },
            now,
        ) {
            Ok(stream_id) => stream_id,
            Err(error) => {
                self.events
                    .qcsd_observe(|_| QcsdObservation::ChaffRequestFailed {
                        resource_id,
                        request_id: Some(request_id),
                    });
                return Err(error);
            }
        };
        self.register_qcsd_stream(
            stream_id,
            QcsdRequestRole::Chaff {
                resource_id,
                request_id: Some(request_id),
            },
            None,
        )?;
        Ok(stream_id)
    }
}

fn same_origin(target: &http::Uri, origin: &(String, String)) -> bool {
    target.scheme_str() == Some(origin.0.as_str())
        && target.authority().map(http::uri::Authority::as_str) == Some(origin.1.as_str())
}

fn strict_chaff_headers(headers: Vec<(String, String)>) -> Vec<Header> {
    // Representation negotiation is part of the frozen workload: replacing
    // Accept-Encoding changes the response body that the size estimate describes.
    sanitize_chaff_headers(headers)
        .into_iter()
        .map(|(name, value)| Header::new(name, value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{same_origin, strict_chaff_headers};

    #[test]
    fn chaff_is_limited_to_the_exact_origin() {
        let origin = ("https".to_owned(), "example.com".to_owned());
        assert!(same_origin(
            &"https://example.com/a".parse().expect("URI"),
            &origin
        ));
        assert!(!same_origin(
            &"https://other.example/a".parse().expect("URI"),
            &origin
        ));
        assert!(!same_origin(
            &"http://example.com/a".parse().expect("URI"),
            &origin
        ));
    }

    #[test]
    fn chaff_headers_preserve_frozen_encoding_and_strip_unsafe_inputs() {
        let headers = strict_chaff_headers(vec![
            ("Accept".into(), "text/html".into()),
            ("Accept-Encoding".into(), "br, gzip".into()),
            ("Accept-Language".into(), "en-AU,en;q=0.9".into()),
            ("Cookie".into(), "secret=1".into()),
            ("Cookie2".into(), "secret=2".into()),
            ("Authorization".into(), "Bearer secret".into()),
            ("Proxy-Authorization".into(), "Basic secret".into()),
            ("If-Match".into(), "etag".into()),
            ("If-None-Match".into(), "etag".into()),
            ("If-Modified-Since".into(), "yesterday".into()),
            ("If-Unmodified-Since".into(), "today".into()),
            ("If-Range".into(), "etag".into()),
            ("Range".into(), "bytes=0-99".into()),
            ("Connection".into(), "keep-alive".into()),
            ("Host".into(), "attacker.example".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("Proxy-Connection".into(), "keep-alive".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Upgrade".into(), "websocket".into()),
            ("TE".into(), "deflate".into()),
            ("te".into(), "trailers".into()),
            (":authority".into(), "attacker.example".into()),
            ("bad name".into(), "unsafe".into()),
            ("x-bad-value".into(), "unsafe\r\nvalue".into()),
        ]);
        assert_eq!(
            headers
                .iter()
                .map(|header| (header.name(), header.value()))
                .collect::<Vec<_>>(),
            vec![
                ("accept", b"text/html".as_slice()),
                ("accept-encoding", b"br, gzip".as_slice()),
                ("accept-language", b"en-AU,en;q=0.9".as_slice()),
                ("te", b"trailers".as_slice()),
            ]
        );
    }

    #[test]
    fn chaff_headers_do_not_inject_an_encoding_policy() {
        let headers = strict_chaff_headers(vec![("Accept".into(), "text/html".into())]);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name(), "accept");
        assert!(
            headers
                .iter()
                .all(|header| header.name() != "accept-encoding")
        );
    }
}
