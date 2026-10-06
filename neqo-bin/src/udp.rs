// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::missing_errors_doc, reason = "Passing up tokio errors.")]

#[cfg(all(feature = "qcsd", target_os = "linux"))]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(feature = "qcsd")]
use std::time::Instant;
use std::{io, net::SocketAddr};

use neqo_common::{datagram, qdebug};
use neqo_udp::{DatagramIter, RecvBuf};

/// Ideally this would live in [`neqo_udp`]. [`neqo_udp`] is used in Firefox.
///
/// Firefox uses `cargo vet`. [`tokio`] the dependency of [`neqo_udp`] is not
/// audited as `safe-to-deploy`. `cargo vet` will require `safe-to-deploy` for
/// [`tokio`] even when behind a feature flag.
///
/// See <https://github.com/mozilla/cargo-vet/issues/626>.
pub struct Socket {
    state: quinn_udp::UdpSocketState,
    inner: tokio::net::UdpSocket,
}

#[cfg(all(feature = "qcsd", target_os = "linux"))]
impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl Socket {
    /// Create a new [`Socket`] bound to the provided address, not managed externally.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        Self::bind_inner(addr, false)
    }

    /// Bind a socket without UDP receive coalescing for direct packet capture.
    pub fn bind_for_direct_capture<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        Self::bind_inner(addr, true)
    }

    fn bind_inner<A: std::net::ToSocketAddrs>(
        addr: A,
        disable_udp_gro: bool,
    ) -> Result<Self, io::Error> {
        const ONE_MB: usize = 1 << 20;

        let socket = std::net::UdpSocket::bind(addr)?;
        let state = quinn_udp::UdpSocketState::new((&socket).into())?;
        if disable_udp_gro {
            neqo_udp::disable_udp_gro(&state, &socket)?;
        }
        #[cfg(apple)]
        // SAFETY: Quinn-udp resolves `sendmsg_x`/`recvmsg_x` via `dlsym` at
        // runtime and falls back to standard `sendmsg`/`recvmsg` if unavailable,
        // so this is safe on all supported Apple OS versions.
        // neqo-bin always enables the Apple fast datapath as a canary.
        unsafe {
            state.set_apple_fast_path();
        }

        // FIXME: We need to experiment if increasing this actually improves performance.
        // Also, on BSD and Apple targets, this seems to increase the `net.inet.udp.maxdgram`
        // sysctl, which is not the same as the socket buffer.
        // if send_buf_before < ONE_MB {
        //     state.set_send_buffer_size((&socket).into(), ONE_MB)?;
        //     let send_buf_after = state.send_buffer_size((&socket).into())?;
        //     qdebug!("Increasing socket send buffer size from {send_buf_before} to {ONE_MB}, now:
        // {send_buf_after}"); } else {
        //     qdebug!("Default socket send buffer size is {send_buf_before}, not changing");
        // }
        qdebug!(
            "Default socket send buffer size is {:?}",
            state.send_buffer_size((&socket).into())
        );

        let recv_buf_before = state.recv_buffer_size((&socket).into())?;
        if recv_buf_before < ONE_MB {
            // Same as Firefox.
            // <https://searchfox.org/mozilla-central/rev/fa5b44a4ea5c98b6a15f39638ea4cd04dc271f3d/modules/libpref/init/StaticPrefList.yaml#13474-13477>
            state.set_recv_buffer_size((&socket).into(), ONE_MB)?;
            qdebug!(
                "Increasing socket recv buffer size from {recv_buf_before} to {ONE_MB}, now: {:?}",
                state.recv_buffer_size((&socket).into())
            );
        } else {
            qdebug!("Default socket receive buffer size is {recv_buf_before}, not changing");
        }

        Ok(Self {
            state,
            inner: tokio::net::UdpSocket::from_std(socket)?,
        })
    }

    /// See [`tokio::net::UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// See [`tokio::net::UdpSocket::writable`].
    pub async fn writable(&self) -> Result<(), io::Error> {
        self.inner.writable().await
    }

    /// See [`tokio::net::UdpSocket::readable`].
    pub async fn readable(&self) -> Result<(), io::Error> {
        self.inner.readable().await
    }

    /// Send a [`datagram::Batch`] on the given [`Socket`].
    pub fn send(&self, d: &datagram::Batch) -> io::Result<()> {
        self.inner.try_io(tokio::io::Interest::WRITABLE, || {
            neqo_udp::send_inner(&self.state, (&self.inner).into(), d)
        })
    }

    /// Send a fidelity-sensitive QCSD [`datagram::Batch`].
    ///
    /// Unlike [`Self::send`], this preserves interface-buffer exhaustion and
    /// message-too-large errors so a dropped defense datagram can never be
    /// receipted as a successful socket handoff.
    #[cfg(feature = "qcsd")]
    pub fn send_qcsd(&self, d: &datagram::Batch) -> io::Result<()> {
        self.inner.try_io(tokio::io::Interest::WRITABLE, || {
            neqo_udp::send_inner_qcsd(&self.state, (&self.inner).into(), d)
        })
    }

    /// Send a fidelity-sensitive QCSD batch and retain the low-level socket
    /// handoff timestamp sampled immediately after the nonblocking send.
    #[cfg(feature = "qcsd")]
    pub fn send_qcsd_timestamped<F: FnOnce() -> Instant>(
        &self,
        d: &datagram::Batch,
        clock: F,
    ) -> io::Result<Instant> {
        self.inner.try_io(tokio::io::Interest::WRITABLE, || {
            neqo_udp::send_inner_qcsd_timestamped(&self.state, (&self.inner).into(), d, clock)
        })
    }

    /// Receive a batch of [`neqo_common::Datagram`]s on the given [`Socket`], each set with
    /// the provided local address.
    pub fn recv<'a>(
        &self,
        local_address: SocketAddr,
        recv_buf: &'a mut RecvBuf,
    ) -> Result<Option<DatagramIter<'a>>, io::Error> {
        self.inner
            .try_io(tokio::io::Interest::READABLE, || {
                neqo_udp::recv_inner(local_address, &self.state, &self.inner, recv_buf)
            })
            .map(Some)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    /// Receive fidelity-sensitive QCSD input and sample its actual syscall entry.
    ///
    /// Tokio may return `WouldBlock` from cached readiness without invoking the
    /// receive closure. Confirm that case with a real UDP receive before
    /// publishing an empty-drain boundary. Both paths sample before the syscall,
    /// so a packet arriving after an empty receive cannot precede a later receipt
    /// timestamp merely because the caller was delayed after that receive.
    #[cfg(feature = "qcsd")]
    pub fn recv_qcsd_timestamped<'a, T, F: FnMut() -> T>(
        &self,
        local_address: SocketAddr,
        recv_buf: &'a mut RecvBuf,
        mut clock: F,
    ) -> (Result<Option<DatagramIter<'a>>, io::Error>, T) {
        // Move this reference only when the closure actually runs. If Tokio
        // skips the closure, the same untouched buffer belongs to the fallback.
        let mut pending_buffer = Some(recv_buf);
        let mut sampled = None;
        let result = self.inner.try_io(tokio::io::Interest::READABLE, || {
            let Some(buffer) = pending_buffer.take() else {
                return Err(io::Error::other("QCSD receive buffer already consumed"));
            };
            sampled = Some(clock());
            neqo_udp::recv_inner(local_address, &self.state, &self.inner, buffer)
        });
        let (result, sampled) = if let Some(sampled) = sampled {
            (result, sampled)
        } else {
            let sampled = clock();
            let result = pending_buffer.map_or_else(
                || Err(io::Error::other("QCSD receive buffer unavailable")),
                |buffer| neqo_udp::recv_inner(local_address, &self.state, &self.inner, buffer),
            );
            (result, sampled)
        };
        (
            result.map(Some).or_else(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(error)
                }
            }),
            sampled,
        )
    }

    pub fn max_gso_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Returns `false` on targets which employ e.g. the `IPV6_DONTFRAG` socket option.
    pub fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

#[cfg(all(test, feature = "qcsd"))]
mod qcsd_receive_tests {
    use std::{cell::Cell, net::UdpSocket, time::Instant};

    use neqo_udp::RecvBuf;

    use super::Socket;

    #[expect(
        clippy::disallowed_methods,
        reason = "real receive boundary regression"
    )]
    fn receive_test_now() -> Instant {
        Instant::now()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn qcsd_recv_confirms_cached_unreadiness_with_an_actual_syscall() {
        let socket = Socket::bind_for_direct_capture("127.0.0.1:0").expect("QCSD receiver");
        let address = socket.local_addr().expect("bound address");
        let mut buffer = RecvBuf::default();
        assert!(
            socket
                .recv(address, &mut buffer)
                .expect("cached unreadiness")
                .is_none()
        );
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let payload = [7_u8; 37];
        sender.send_to(&payload, address).expect("queued UDP packet");

        // No await between send and receive: the Tokio reactor has not had a
        // turn to refresh readiness. Its generic API still reports None.
        assert!(
            socket
                .recv(address, &mut buffer)
                .expect("unpolled readiness")
                .is_none()
        );
        let samples = Cell::new(0);
        let (received, boundary) = socket.recv_qcsd_timestamped(address, &mut buffer, || {
            samples.set(samples.get() + 1);
            123_u64
        });
        let datagrams: Vec<_> = received
            .expect("real receive")
            .expect("queued packet")
            .collect();
        assert_eq!(samples.get(), 1);
        assert_eq!(boundary, 123);
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].len(), payload.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn qcsd_recv_empty_boundary_precedes_late_packet_and_delayed_caller_clock() {
        let socket = Socket::bind_for_direct_capture("127.0.0.1:0").expect("QCSD receiver");
        let address = socket.local_addr().expect("bound address");
        let mut buffer = RecvBuf::default();
        let samples = Cell::new(0);
        let (received, empty_receive_entry) = socket.recv_qcsd_timestamped(address, &mut buffer, || {
            samples.set(samples.get() + 1);
            receive_test_now()
        });
        assert!(received.expect("actual empty receive").is_none());
        let after_empty_receive = receive_test_now();
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender
            .send_to(&[9_u8; 32], address)
            .expect("late UDP packet");
        // This wait represents delayed caller-side receipt rendering. The
        // retained boundary must not move to this later wall/monotonic sample.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let delayed_caller_clock = receive_test_now();
        assert_eq!(samples.get(), 1);
        assert!(empty_receive_entry <= after_empty_receive);
        assert!(after_empty_receive < delayed_caller_clock);
        let (received, next_entry) =
            socket.recv_qcsd_timestamped(address, &mut buffer, receive_test_now);
        assert_eq!(
            received
                .expect("late actual receive")
                .expect("late packet")
                .count(),
            1
        );
        assert!(empty_receive_entry < next_entry);
    }
}
