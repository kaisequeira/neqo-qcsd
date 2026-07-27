// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

//! Narrow, feature-gated adapter between HTTP/3 and the transport-independent
//! QCSD controller.

use std::time::{Duration, Instant};

use neqo_common::Header;
use neqo_csdef::{
    QcsdAction, QcsdChaffRequestId, QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdStreamId,
    Resource,
};
use neqo_transport::StreamId;

use super::Http3Client;
use crate::{Error, Priority, Res};

impl Http3Client {
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
        let scheme = origin.scheme_str().ok_or(Error::InvalidInput)?;
        let authority = origin.authority().ok_or(Error::InvalidInput)?.as_str();
        if scheme != "https" {
            return Err(Error::InvalidInput);
        }
        self.qcsd_endpoint = Some(endpoint);
        self.qcsd_origin = Some((scheme.to_owned(), authority.to_owned()));
        self.events.qcsd_enable(endpoint);
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
        self.conn.qcsd_enable(endpoint, shape_stream_sends);
        self.conn
            .qcsd_set_keep_alive_lead_time(keep_alive_lead_time);
        Ok(())
    }

    /// Register the application/chaff role of a request stream with QCSD.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] when QCSD has not been enabled.
    pub fn register_qcsd_stream(&mut self, stream_id: StreamId, role: QcsdRequestRole) -> Res<()> {
        let endpoint = self.qcsd_endpoint.ok_or(Error::InvalidInput)?;
        self.conn.qcsd_register_stream_role(stream_id, role)?;
        self.events.qcsd_observe(|_| QcsdObservation::StreamOpened {
            endpoint,
            stream: QcsdStreamId(stream_id.as_u64()),
            role,
        });
        Ok(())
    }

    /// Drain observations accumulated by the HTTP/3 and transport adapters.
    #[must_use]
    pub fn qcsd_observations(&mut self) -> Vec<QcsdObservation> {
        let mut observations = self.events.qcsd_observations();
        observations.extend(self.conn.qcsd_observations());
        observations
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
        let stream_id = match self.fetch(now, "GET", &target, &headers, Priority::default()) {
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
        )?;
        Ok(stream_id)
    }
}

fn same_origin(target: &http::Uri, origin: &(String, String)) -> bool {
    target.scheme_str() == Some(origin.0.as_str())
        && target.authority().map(http::uri::Authority::as_str) == Some(origin.1.as_str())
}

fn strict_chaff_headers(headers: Vec<(String, String)>) -> Vec<Header> {
    let mut headers = headers
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            (!matches!(
                name.as_str(),
                "accept-encoding"
                    | "authorization"
                    | "cookie"
                    | "if-match"
                    | "if-modified-since"
                    | "if-none-match"
                    | "if-range"
                    | "if-unmodified-since"
                    | "proxy-authorization"
                    | "range"
            ))
            .then(|| Header::new(name, value))
        })
        .collect::<Vec<_>>();
    headers.push(Header::new("accept-encoding", "identity"));
    headers
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
    fn chaff_headers_are_identity_encoded_and_non_sensitive() {
        let headers = strict_chaff_headers(vec![
            ("Accept".into(), "text/html".into()),
            ("Accept-Encoding".into(), "br, gzip".into()),
            ("Cookie".into(), "secret=1".into()),
            ("Authorization".into(), "Bearer secret".into()),
            ("If-None-Match".into(), "etag".into()),
            ("Range".into(), "bytes=0-99".into()),
        ]);
        assert!(headers.iter().any(|header| header.name() == "accept"));
        assert_eq!(
            headers
                .iter()
                .filter(|header| header.name() == "accept-encoding")
                .map(neqo_common::Header::value)
                .collect::<Vec<_>>(),
            vec![b"identity".as_slice()]
        );
        assert!(!headers.iter().any(|header| matches!(
            header.name(),
            "cookie" | "authorization" | "if-none-match" | "range"
        )));
    }
}
