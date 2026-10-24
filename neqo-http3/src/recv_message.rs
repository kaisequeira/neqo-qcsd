// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    cmp::min,
    collections::VecDeque,
    fmt::{self, Debug, Display, Formatter},
    rc::Rc,
    time::Instant,
};

use neqo_common::{Header, header::HeadersExt as _, qdebug, qinfo, qtrace};
use neqo_qpack as qpack;
use neqo_transport::{Connection, StreamId};

#[cfg(feature = "qcsd")]
use crate::frames::QcsdStreamReaderConnectionWrapper;
#[cfg(not(feature = "qcsd"))]
use crate::frames::StreamReaderConnectionWrapper;
use crate::{
    CloseType, Error, Http3StreamInfo, Http3StreamType, HttpRecvStream, HttpRecvStreamEvents,
    MessageType, Priority, PushId, ReceiveOutput, RecvStream, Res, Stream,
    frames::{FrameReader, HFrame, hframe::HFrameType},
    headers_checks::{headers_valid, is_interim},
    priority::PriorityHandler,
    push_controller::PushController,
    qlog,
};

pub struct RecvMessageInfo {
    pub message_type: MessageType,
    pub stream_type: Http3StreamType,
    pub stream_id: StreamId,
    pub first_frame_type: Option<u64>,
}

/*
 * Response stream state:
 *    WaitingForResponseHeaders : we wait for headers. in this state we can
 *                                also get a PUSH_PROMISE frame.
 *    DecodingHeaders : In this step the headers will be decoded. The stream
 *                      may be blocked in this state on encoder instructions.
 *    WaitingForData : we got HEADERS, we are waiting for one or more data
 *                     frames. In this state we can receive one or more
 *                     PUSH_PROMIS frames or a HEADERS frame carrying trailers.
 *    ReadingData : we got a DATA frame, now we letting the app read payload.
 *                  From here we will go back to WaitingForData state to wait
 *                  for more data frames or to CLosed state
 *    ClosePending : waiting for app to pick up data, after that we can delete
 * the TransactionClient.
 *    Closed
 *    ExtendedConnect: this request is for a WebTransport session. In this
 *                         state RecvMessage will not be treated as a HTTP
 *                         stream anymore. It is waiting to be transformed
 *                         into WebTransport session or to be closed.
 */
#[derive(Debug)]
enum RecvMessageState {
    WaitingForResponseHeaders { frame_reader: FrameReader },
    DecodingHeaders { header_block: Vec<u8>, fin: bool },
    WaitingForData { frame_reader: FrameReader },
    ReadingData { remaining_data_len: usize },
    WaitingForFinAfterTrailers { frame_reader: FrameReader },
    ClosePending, // Close must first be read by application
    Closed,
    ExtendedConnect,
}

#[derive(Debug)]
struct PushInfo {
    push_id: PushId,
    header_block: Vec<u8>,
}

#[cfg(feature = "qcsd")]
fn qcsd_publish_peer_fin_read(
    conn: &mut Connection,
    stream_id: StreamId,
    conn_events: &dyn HttpRecvStreamEvents,
) -> Res<()> {
    if let Some(proof) = conn.qcsd_take_stream_peer_fin_read(stream_id)? {
        conn_events.qcsd_peer_fin_read(proof);
    }
    Ok(())
}

#[cfg(feature = "qcsd")]
fn receive_frame(
    frame_reader: &mut FrameReader,
    conn: &mut Connection,
    stream_id: StreamId,
    conn_events: &dyn HttpRecvStreamEvents,
    now: Instant,
) -> Res<(Option<HFrame>, bool)> {
    let observe = |bytes| conn_events.qcsd_bytes_read(stream_id, bytes);
    let received = frame_reader.receive(
        &mut QcsdStreamReaderConnectionWrapper::new(conn, stream_id, &observe),
        now,
    )?;
    if received.1 {
        qcsd_publish_peer_fin_read(conn, stream_id, conn_events)?;
    }
    Ok(received)
}

#[cfg(not(feature = "qcsd"))]
fn receive_frame(
    frame_reader: &mut FrameReader,
    conn: &mut Connection,
    stream_id: StreamId,
    _conn_events: &dyn HttpRecvStreamEvents,
    now: Instant,
) -> Res<(Option<HFrame>, bool)> {
    frame_reader.receive(
        &mut StreamReaderConnectionWrapper::new(conn, stream_id),
        now,
    )
}

#[derive(Debug)]
pub struct RecvMessage {
    state: RecvMessageState,
    stream_info: Http3StreamInfo,
    message_type: MessageType,
    stream_type: Http3StreamType,
    qpack_decoder: Rc<RefCell<qpack::Decoder>>,
    conn_events: Box<dyn HttpRecvStreamEvents>,
    push_handler: Option<Rc<RefCell<PushController>>>,
    stream_id: StreamId,
    priority_handler: PriorityHandler,
    blocked_push_promise: VecDeque<PushInfo>,
    #[cfg(feature = "qcsd")]
    qcsd_header_frame_bytes: u64,
}

impl Display for RecvMessage {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "RecvMessage {}", self.stream_id)
    }
}

impl RecvMessage {
    pub fn new(
        message_info: &RecvMessageInfo,
        qpack_decoder: Rc<RefCell<qpack::Decoder>>,
        conn_events: Box<dyn HttpRecvStreamEvents>,
        push_handler: Option<Rc<RefCell<PushController>>>,
        priority_handler: PriorityHandler,
    ) -> Self {
        Self {
            state: RecvMessageState::WaitingForResponseHeaders {
                frame_reader: message_info
                    .first_frame_type
                    .map_or_else(FrameReader::new, |frame_type| {
                        FrameReader::new_with_type(HFrameType(frame_type))
                    }),
            },
            stream_info: Http3StreamInfo::new(message_info.stream_id, Http3StreamType::Http),
            message_type: message_info.message_type,
            stream_type: message_info.stream_type,
            qpack_decoder,
            conn_events,
            push_handler,
            stream_id: message_info.stream_id,
            priority_handler,
            blocked_push_promise: VecDeque::new(),
            #[cfg(feature = "qcsd")]
            qcsd_header_frame_bytes: 0,
        }
    }

    fn handle_headers_frame(
        &mut self,
        header_block: Vec<u8>,
        fin: bool,
        #[cfg(feature = "qcsd")] frame_bytes: u64,
    ) -> Res<()> {
        #[cfg(feature = "qcsd")]
        {
            self.qcsd_header_frame_bytes = frame_bytes;
        }
        match self.state {
            RecvMessageState::WaitingForResponseHeaders { .. } => {
                if header_block.is_empty() {
                    return Err(Error::HttpGeneralProtocolStream);
                }
                self.state = RecvMessageState::DecodingHeaders { header_block, fin };
            }
            RecvMessageState::WaitingForData { .. } => {
                // TODO implement trailers, for now just ignore them.
                #[cfg(feature = "qcsd")]
                self.conn_events.qcsd_response_headers(
                    self.stream_id,
                    self.qcsd_header_frame_bytes,
                    &[],
                );
                self.state = RecvMessageState::WaitingForFinAfterTrailers {
                    frame_reader: FrameReader::new(),
                };
            }
            RecvMessageState::WaitingForFinAfterTrailers { .. } => {
                return Err(Error::HttpFrameUnexpected);
            }
            _ => unreachable!(
                "This functions is only called in WaitingForResponseHeaders | WaitingForData | WaitingForFinAfterTrailers state"
            ),
        }
        Ok(())
    }

    fn handle_data_frame(
        &mut self,
        len: u64,
        fin: bool,
        #[cfg(feature = "qcsd")] frame_header_bytes: u64,
    ) -> Res<()> {
        #[cfg(feature = "qcsd")]
        self.conn_events
            .qcsd_data_frame(self.stream_id, frame_header_bytes, len);
        match self.state {
            RecvMessageState::WaitingForResponseHeaders { .. }
            | RecvMessageState::WaitingForFinAfterTrailers { .. } => {
                return Err(Error::HttpFrameUnexpected);
            }
            RecvMessageState::WaitingForData { .. } => {
                if len > 0 {
                    if fin {
                        return Err(Error::HttpFrame);
                    }
                    self.state = RecvMessageState::ReadingData {
                        remaining_data_len: usize::try_from(len).or(Err(Error::HttpFrame))?,
                    };
                }
            }
            _ => unreachable!(
                "This functions is only called in WaitingForResponseHeaders | WaitingForData | WaitingForFinAfterTrailers state"
            ),
        }
        Ok(())
    }

    fn add_headers(&mut self, mut headers: Vec<Header>, fin: bool) -> Res<()> {
        qtrace!("[{self}] Add new headers fin={fin}");
        let interim = match self.message_type {
            MessageType::Request => false,
            MessageType::Response => is_interim(&headers)?,
        };
        headers_valid(&headers, self.message_type)?;
        if self.message_type == MessageType::Response {
            headers.retain(Header::is_allowed_for_response);
        }

        if fin && interim {
            return Err(Error::HttpGeneralProtocolStream);
        }

        #[cfg(feature = "qcsd")]
        if self.message_type == MessageType::Response {
            self.conn_events.qcsd_response_headers(
                self.stream_id,
                self.qcsd_header_frame_bytes,
                &headers,
            );
        }

        let is_extended_connect = self.message_type == MessageType::Request
            && headers.contains_header(":method", "CONNECT")
            && headers.find_header(":protocol").is_some();
        if is_extended_connect {
            self.conn_events
                .extended_connect_new_session(self.stream_id, headers);
        } else {
            self.conn_events
                .header_ready(&self.stream_info, headers, interim, fin);
        }

        if fin {
            self.set_closed();
        } else {
            self.state = if is_extended_connect {
                self.stream_type = Http3StreamType::ExtendedConnect;
                RecvMessageState::ExtendedConnect
            } else if interim {
                RecvMessageState::WaitingForResponseHeaders {
                    frame_reader: FrameReader::new(),
                }
            } else {
                RecvMessageState::WaitingForData {
                    frame_reader: FrameReader::new(),
                }
            };
        }
        Ok(())
    }

    fn set_state_to_close_pending(&mut self, post_readable_event: bool) -> Res<()> {
        // Stream has received fin. Depending on headers state set header_ready
        // or data_readable event so that app can pick up the fin.
        qtrace!(
            "[{self}] set_state_to_close_pending: state={:?}",
            self.state
        );

        match self.state {
            RecvMessageState::WaitingForResponseHeaders { .. } => {
                return Err(Error::HttpGeneralProtocolStream);
            }
            RecvMessageState::ReadingData { .. } => {}
            RecvMessageState::WaitingForData { .. }
            | RecvMessageState::WaitingForFinAfterTrailers { .. } => {
                if post_readable_event {
                    self.conn_events.data_readable(&self.stream_info);
                }
            }
            _ => unreachable!("Closing an already closed transaction"),
        }
        if !matches!(self.state, RecvMessageState::Closed) {
            self.state = RecvMessageState::ClosePending;
        }
        Ok(())
    }

    fn handle_push_promise(
        &mut self,
        push_id: PushId,
        header_block: Vec<u8>,
        #[cfg(feature = "qcsd")] frame_bytes: u64,
    ) -> Res<()> {
        if self.push_handler.is_none() {
            return Err(Error::HttpFrameUnexpected);
        }

        #[cfg(feature = "qcsd")]
        {
            self.conn_events
                .qcsd_push_promise_frame(self.stream_id, frame_bytes);
        }

        if !self.blocked_push_promise.is_empty() {
            self.blocked_push_promise.push_back(PushInfo {
                push_id,
                header_block,
            });
        } else if let Some(headers) = self
            .qpack_decoder
            .borrow_mut()
            .decode_header_block(&header_block, self.stream_id)?
        {
            self.push_handler
                .as_ref()
                .ok_or(Error::HttpFrameUnexpected)?
                .borrow_mut()
                .new_push_promise(push_id, self.stream_id, headers)?;
        } else {
            self.blocked_push_promise.push_back(PushInfo {
                push_id,
                header_block,
            });
        }
        Ok(())
    }

    fn handle_frame(
        &mut self,
        frame: HFrame,
        fin: bool,
        #[cfg(feature = "qcsd")] frame_bytes: u64,
    ) -> Res<()> {
        match frame {
            HFrame::Headers { header_block } => self.handle_headers_frame(
                header_block,
                fin,
                #[cfg(feature = "qcsd")]
                frame_bytes,
            ),
            HFrame::Data { len } => self.handle_data_frame(
                len,
                fin,
                #[cfg(feature = "qcsd")]
                frame_bytes,
            ),
            HFrame::PushPromise {
                push_id,
                header_block,
            } => self.handle_push_promise(
                push_id,
                header_block,
                #[cfg(feature = "qcsd")]
                frame_bytes,
            ),
            _ => Err(Error::HttpFrameUnexpected),
        }
    }

    #[cfg(feature = "qcsd")]
    fn qcsd_observe_ignored(
        conn_events: &dyn HttpRecvStreamEvents,
        stream_id: StreamId,
        frame_reader: &mut FrameReader,
    ) {
        let frame_bytes = frame_reader.qcsd_take_ignored_frame_bytes();
        if frame_bytes > 0 {
            conn_events.qcsd_ignored_request_stream_frame(stream_id, frame_bytes);
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keeping this state machine in one place makes transitions auditable"
    )]
    fn receive_internal(
        &mut self,
        conn: &mut Connection,
        post_readable_event: bool,
        now: Instant,
    ) -> Res<()> {
        loop {
            qdebug!("[{self}] state={:?}", self.state);
            #[cfg(feature = "qcsd")]
            let waiting_for_data = matches!(&self.state, RecvMessageState::WaitingForData { .. });
            match &mut self.state {
                // In the following 3 states we need to read frames.
                RecvMessageState::WaitingForResponseHeaders { frame_reader }
                | RecvMessageState::WaitingForData { frame_reader }
                | RecvMessageState::WaitingForFinAfterTrailers { frame_reader } => {
                    let received = receive_frame(
                        frame_reader,
                        conn,
                        self.stream_id,
                        self.conn_events.as_ref(),
                        now,
                    )?;
                    #[cfg(feature = "qcsd")]
                    Self::qcsd_observe_ignored(
                        self.conn_events.as_ref(),
                        self.stream_id,
                        frame_reader,
                    );
                    match received {
                        (None, true) => {
                            break self.set_state_to_close_pending(post_readable_event);
                        }
                        (None, false) => {
                            #[cfg(feature = "qcsd")]
                            self.conn_events.qcsd_header_progress(
                                self.stream_id,
                                u64::try_from(frame_reader.qcsd_min_remaining())
                                    .map_err(|_| Error::Internal)?,
                                waiting_for_data && frame_reader.qcsd_at_frame_boundary(),
                            );
                            break Ok(());
                        }
                        (Some(frame), fin) => {
                            #[cfg(feature = "qcsd")]
                            let frame_bytes = frame_reader.qcsd_last_frame_bytes();
                            qdebug!(
                                "[{self}] recv frame: {frame:?}; state={:?} fin={fin}",
                                self.state,
                            );
                            self.handle_frame(
                                frame,
                                fin,
                                #[cfg(feature = "qcsd")]
                                frame_bytes,
                            )?;
                            if matches!(self.state, RecvMessageState::Closed) {
                                break Ok(());
                            }
                            if fin
                                && !matches!(self.state, RecvMessageState::DecodingHeaders { .. })
                            {
                                break self.set_state_to_close_pending(post_readable_event);
                            }
                        }
                    }
                }
                RecvMessageState::DecodingHeaders { header_block, fin } => {
                    if self
                        .qpack_decoder
                        .borrow()
                        .refers_dynamic_table(header_block)?
                        && !self.blocked_push_promise.is_empty()
                    {
                        qinfo!(
                            "[{self}] decoding header is blocked waiting for a push_promise header block"
                        );
                        break Ok(());
                    }
                    let done = *fin;
                    let d_headers = self
                        .qpack_decoder
                        .borrow_mut()
                        .decode_header_block(header_block, self.stream_id)?;
                    if let Some(headers) = d_headers {
                        self.add_headers(headers, done)?;
                        if matches!(
                            self.state,
                            RecvMessageState::Closed | RecvMessageState::ExtendedConnect
                        ) {
                            break Ok(());
                        }
                    } else {
                        qinfo!("[{self}] decoding header is blocked");
                        break Ok(());
                    }
                }
                RecvMessageState::ReadingData { .. } => {
                    if post_readable_event {
                        self.conn_events.data_readable(&self.stream_info);
                    }
                    break Ok(());
                }
                RecvMessageState::ClosePending | RecvMessageState::Closed => {
                    panic!("Stream readable after being closed!");
                }
                RecvMessageState::ExtendedConnect => {
                    // Ignore read event, this request is waiting to be picked up by a new
                    // WebTransportSession
                    break Ok(());
                }
            }
        }
    }

    fn set_closed(&mut self) {
        if !self.blocked_push_promise.is_empty() {
            self.qpack_decoder
                .borrow_mut()
                .cancel_stream(self.stream_id);
        }
        self.state = RecvMessageState::Closed;
        self.conn_events
            .recv_closed(&self.stream_info, CloseType::Done);
    }

    const fn closing(&self) -> bool {
        matches!(
            self.state,
            RecvMessageState::ClosePending | RecvMessageState::Closed
        )
    }
}

impl Stream for RecvMessage {
    fn stream_type(&self) -> Http3StreamType {
        self.stream_type
    }
}

impl RecvStream for RecvMessage {
    fn receive(&mut self, conn: &mut Connection, now: Instant) -> Res<(ReceiveOutput, bool)> {
        self.receive_internal(conn, true, now)?;
        Ok((
            ReceiveOutput::NoOutput,
            matches!(self.state, RecvMessageState::Closed),
        ))
    }

    fn reset(&mut self, close_type: CloseType) -> Res<()> {
        if !self.closing() || !self.blocked_push_promise.is_empty() {
            self.qpack_decoder
                .borrow_mut()
                .cancel_stream(self.stream_id);
        }
        self.conn_events.recv_closed(&self.stream_info, close_type);
        self.state = RecvMessageState::Closed;
        Ok(())
    }

    fn read_data(
        &mut self,
        conn: &mut Connection,
        buf: &mut [u8],
        now: Instant,
    ) -> Res<(usize, bool)> {
        let mut written = 0;
        loop {
            match self.state {
                RecvMessageState::ReadingData {
                    ref mut remaining_data_len,
                } => {
                    let to_read = min(*remaining_data_len, buf.len() - written);
                    let (amount, fin) = conn
                        .stream_recv(self.stream_id, &mut buf[written..written + to_read])
                        .map_err(|e| Error::map_stream_recv_errors(&Error::from(e)))?;
                    qlog::h3_data_moved_up(conn.qlog_mut(), self.stream_id, amount, now);
                    #[cfg(feature = "qcsd")]
                    self.conn_events.qcsd_bytes_read(
                        self.stream_id,
                        u64::try_from(amount).map_err(|_| Error::Internal)?,
                    );

                    debug_assert!(amount <= to_read);
                    *remaining_data_len -= amount;
                    written += amount;

                    if fin {
                        if *remaining_data_len > 0 {
                            return Err(Error::HttpFrame);
                        }
                        #[cfg(feature = "qcsd")]
                        qcsd_publish_peer_fin_read(
                            conn,
                            self.stream_id,
                            self.conn_events.as_ref(),
                        )?;
                        self.set_closed();
                        break Ok((written, fin));
                    } else if *remaining_data_len == 0 {
                        self.state = RecvMessageState::WaitingForData {
                            frame_reader: FrameReader::new(),
                        };
                        self.receive_internal(conn, false, now)?;
                    } else {
                        break Ok((written, false));
                    }
                }
                RecvMessageState::ClosePending => {
                    self.set_closed();
                    break Ok((written, true));
                }
                _ => break Ok((written, false)),
            }
        }
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        Some(self)
    }
}

impl HttpRecvStream for RecvMessage {
    #[cfg(feature = "qcsd")]
    fn qcsd_cs_terminal_receive_ready(&self, kind: crate::QcsdCsTerminalReceiveKind) -> Res<()> {
        if self.stream_type != Http3StreamType::Http
            || self.message_type != MessageType::Response
            || !self.blocked_push_promise.is_empty()
            || self.qpack_decoder.borrow().is_stream_blocked(self.stream_id)
        {
            return Err(Error::InvalidInput);
        }
        let allowed = match kind {
            crate::QcsdCsTerminalReceiveKind::Drained => match &self.state {
                RecvMessageState::WaitingForResponseHeaders { frame_reader } =>
                    frame_reader.qcsd_partial_initial_headers(),
                RecvMessageState::ReadingData { remaining_data_len } => *remaining_data_len > 0,
                RecvMessageState::WaitingForData { frame_reader } => frame_reader.qcsd_at_frame_boundary(),
                _ => false,
            },
            crate::QcsdCsTerminalReceiveKind::IdleInitial => matches!(&self.state,
                RecvMessageState::WaitingForResponseHeaders { frame_reader }
                    if frame_reader.qcsd_untouched_initial_frame()),
            crate::QcsdCsTerminalReceiveKind::ParserAllowance => matches!(&self.state,
                RecvMessageState::WaitingForData { frame_reader }
                    if frame_reader.qcsd_at_frame_boundary()),
        };
        if !allowed { return Err(Error::InvalidInput); }
        Ok(())
    }

    #[cfg(feature = "qcsd")]
    fn qcsd_abandon_drained_response(&mut self) -> Res<&'static str> {
        if self.stream_type != Http3StreamType::Http
            || self.message_type != MessageType::Response
            || !self.blocked_push_promise.is_empty()
            || self
                .qpack_decoder
                .borrow()
                .is_stream_blocked(self.stream_id)
            || self.qpack_decoder.borrow().has_pending_send()
        {
            return Err(Error::InvalidInput);
        }
        let receive_state = match &self.state {
            RecvMessageState::ReadingData { remaining_data_len } if *remaining_data_len > 0 => {
                "reading-data"
            }
            RecvMessageState::WaitingForData { frame_reader }
                if frame_reader.qcsd_at_frame_boundary() =>
            {
                "waiting-for-data-at-frame-boundary"
            }
            _ => return Err(Error::InvalidInput),
        };
        // Calling reset() here would create a QPACK StreamCancellation. A
        // local error notification purges queued application events without
        // inventing a peer FIN/RESET or changing transport receive state.
        self.state = RecvMessageState::Closed;
        self.conn_events.recv_closed(
            &self.stream_info,
            CloseType::LocalError(Error::HttpRequestCancelled.code()),
        );
        Ok(receive_state)
    }

    #[cfg(feature = "qcsd")]
    fn qcsd_abandon_cs_drained_response(&mut self) -> Res<&'static str> {
        if self.stream_type != Http3StreamType::Http
            || self.message_type != MessageType::Response
            || !self.blocked_push_promise.is_empty()
            || self
                .qpack_decoder
                .borrow()
                .is_stream_blocked(self.stream_id)
            || self.qpack_decoder.borrow().has_pending_send()
        {
            return Err(Error::InvalidInput);
        }
        let receive_state = match &self.state {
            RecvMessageState::WaitingForResponseHeaders { frame_reader }
                if frame_reader.qcsd_partial_initial_headers() =>
            {
                "cs-reading-initial-headers"
            }
            RecvMessageState::ReadingData { remaining_data_len } if *remaining_data_len > 0 => {
                "reading-data"
            }
            RecvMessageState::WaitingForData { frame_reader }
                if frame_reader.qcsd_at_frame_boundary() =>
            {
                "waiting-for-data-at-frame-boundary"
            }
            _ => return Err(Error::InvalidInput),
        };
        // This is local application cleanup, not peer FIN/RESET or QPACK
        // cancellation. The caller has independently proved transport drain.
        self.state = RecvMessageState::Closed;
        self.conn_events.recv_closed(
            &self.stream_info,
            CloseType::LocalError(Error::HttpRequestCancelled.code()),
        );
        Ok(receive_state)
    }

    #[cfg(feature = "qcsd")]
    fn qcsd_abandon_cs_idle_initial_response(&mut self) -> Res<&'static str> {
        if self.stream_type != Http3StreamType::Http
            || self.message_type != MessageType::Response
            || !self.blocked_push_promise.is_empty()
            || self
                .qpack_decoder
                .borrow()
                .is_stream_blocked(self.stream_id)
            || self.qpack_decoder.borrow().has_pending_send()
            || !matches!(&self.state,
                RecvMessageState::WaitingForResponseHeaders { frame_reader }
                    if frame_reader.qcsd_untouched_initial_frame())
        {
            return Err(Error::InvalidInput);
        }
        // No HEADERS/QPACK decoder has run. Do not read/discard buffered QUIC
        // bytes and do not reset either protocol layer.
        self.state = RecvMessageState::Closed;
        self.conn_events.recv_closed(
            &self.stream_info,
            CloseType::LocalError(Error::HttpRequestCancelled.code()),
        );
        Ok("cs-untouched-initial-response")
    }

    #[cfg(feature = "qcsd")]
    fn qcsd_abandon_cs_parser_allowance_response(&mut self) -> Res<&'static str> {
        if self.stream_type != Http3StreamType::Http
            || self.message_type != MessageType::Response
            || !self.blocked_push_promise.is_empty()
            || self
                .qpack_decoder
                .borrow()
                .is_stream_blocked(self.stream_id)
            || self.qpack_decoder.borrow().has_pending_send()
            || !matches!(&self.state, RecvMessageState::WaitingForData { frame_reader }
                if frame_reader.qcsd_at_frame_boundary())
        {
            return Err(Error::InvalidInput);
        }
        // No parser read, cancellation or transport mutation. The controller
        // suffix and fresh QUIC offsets were checked by the distinct caller.
        self.state = RecvMessageState::Closed;
        self.conn_events.recv_closed(
            &self.stream_info,
            CloseType::LocalError(Error::HttpRequestCancelled.code()),
        );
        Ok("cs-unused-parser-allowance-at-frame-boundary")
    }

    fn header_unblocked(
        &mut self,
        conn: &mut Connection,
        now: Instant,
    ) -> Res<(ReceiveOutput, bool)> {
        while let Some(p) = self.blocked_push_promise.front() {
            if let Some(headers) = self
                .qpack_decoder
                .borrow_mut()
                .decode_header_block(&p.header_block, self.stream_id)?
            {
                self.push_handler
                    .as_ref()
                    .ok_or(Error::HttpFrameUnexpected)?
                    .borrow_mut()
                    .new_push_promise(p.push_id, self.stream_id, headers)?;
                self.blocked_push_promise.pop_front();
            } else {
                return Ok((ReceiveOutput::NoOutput, false));
            }
        }

        self.receive(conn, now)
    }

    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        Ok(self.priority_handler.maybe_update_priority(priority))
    }

    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.priority_handler.maybe_encode_frame(self.stream_id)
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        self.priority_handler.priority_update_sent();
        Ok(())
    }

    fn set_new_listener(&mut self, conn_events: Box<dyn HttpRecvStreamEvents>) {
        self.state = RecvMessageState::WaitingForData {
            frame_reader: FrameReader::new(),
        };
        self.conn_events = conn_events;
    }

    fn extended_connect_wait_for_response(&self) -> bool {
        matches!(self.state, RecvMessageState::ExtendedConnect)
    }
}

#[cfg(all(test, feature = "qcsd"))]
mod local_abandon_tests {
    use neqo_common::event::Provider as _;
    use neqo_transport::StreamType;

    use super::*;
    use crate::{
        RecvStreamEvents as _,
        client_events::{Http3ClientEvent, Http3ClientEvents},
    };

    // Parser-only component fixture. The real connected HTTP/3 regression is
    // in the runner tests; no transport eligibility is asserted here.
    fn response() -> (RecvMessage, Http3ClientEvents) {
        let (mut connection, _peer) = test_fixture::connect();
        let mut decoder = qpack::Decoder::new(&qpack::Settings::default());
        let decoder_stream = connection.stream_create(StreamType::UniDi).unwrap();
        decoder.add_send_stream(decoder_stream);
        decoder.send(&mut connection).unwrap();
        assert!(!decoder.has_pending_send());
        let events = Http3ClientEvents::default();
        let mut response = RecvMessage::new(
            &RecvMessageInfo {
                message_type: MessageType::Response,
                stream_type: Http3StreamType::Http,
                stream_id: StreamId::new(348),
                first_frame_type: None,
            },
            Rc::new(RefCell::new(decoder)),
            Box::new(events.clone()),
            None,
            PriorityHandler::new(false, Priority::default()),
        );
        response.state = RecvMessageState::ReadingData {
            remaining_data_len: 69,
        };
        (response, events)
    }

    #[test]
    fn qcsd_local_abandon_parser_notifies_only_local_error_without_qpack() {
        let (mut response, mut events) = response();
        events.data_readable(&response.stream_info);
        assert_eq!(response.qcsd_abandon_drained_response(), Ok("reading-data"));
        assert!(matches!(response.state, RecvMessageState::Closed));
        assert!(!response.qpack_decoder.borrow().has_pending_send());
        assert!(matches!(events.next_event(), Some(Http3ClientEvent::Reset {
            stream_id, error: 268, local: true,
        }) if stream_id == StreamId::new(348)));
        assert!(
            events.next_event().is_none(),
            "queued readable event was purged"
        );
    }

    #[test]
    fn qcsd_local_abandon_parser_accepts_exact_waiting_data_boundary() {
        let (mut response, _events) = response();
        response.state = RecvMessageState::WaitingForData {
            frame_reader: FrameReader::new(),
        };
        assert_eq!(
            response.qcsd_abandon_drained_response(),
            Ok("waiting-for-data-at-frame-boundary")
        );
    }

    #[test]
    fn qcsd_local_abandon_parser_refuses_headers_partial_frame_trailers_and_terminal_states() {
        let states = [
            RecvMessageState::WaitingForResponseHeaders {
                frame_reader: FrameReader::new(),
            },
            RecvMessageState::DecodingHeaders {
                header_block: vec![0],
                fin: false,
            },
            RecvMessageState::WaitingForData {
                frame_reader: FrameReader::new_with_type(HFrameType(0)),
            },
            RecvMessageState::WaitingForFinAfterTrailers {
                frame_reader: FrameReader::new(),
            },
            RecvMessageState::ReadingData {
                remaining_data_len: 0,
            },
            RecvMessageState::ClosePending,
            RecvMessageState::Closed,
            RecvMessageState::ExtendedConnect,
        ];
        for state in states {
            let (mut response, mut events) = response();
            response.state = state;
            let before = format!("{:?}", response.state);
            assert_eq!(
                response.qcsd_abandon_drained_response(),
                Err(Error::InvalidInput)
            );
            assert_eq!(format!("{:?}", response.state), before);
            assert!(events.next_event().is_none());
            assert!(!response.qpack_decoder.borrow().has_pending_send());
        }
    }

    #[test]
    fn qcsd_local_abandon_parser_refuses_request_and_extended_connect_types() {
        let (mut request, _events) = response();
        request.message_type = MessageType::Request;
        assert_eq!(
            request.qcsd_abandon_drained_response(),
            Err(Error::InvalidInput)
        );
        let (mut extended, _events) = response();
        extended.stream_type = Http3StreamType::ExtendedConnect;
        assert_eq!(
            extended.qcsd_abandon_drained_response(),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn qcsd_local_abandon_parser_refuses_blocked_push_promise_without_mutation() {
        let (mut response, mut events) = response();
        response.blocked_push_promise.push_back(PushInfo {
            push_id: PushId::new(1),
            header_block: vec![0x02, 0x80, 0x10],
        });
        assert_eq!(
            response.qcsd_abandon_drained_response(),
            Err(Error::InvalidInput)
        );
        assert_eq!(response.blocked_push_promise.len(), 1);
        assert!(matches!(
            response.state,
            RecvMessageState::ReadingData { .. }
        ));
        assert!(events.next_event().is_none());
        assert!(!response.qpack_decoder.borrow().has_pending_send());
    }

    #[test]
    fn qcsd_local_abandon_parser_refuses_pending_and_blocked_qpack() {
        let (mut pending, mut events) = response();
        pending.qpack_decoder = Rc::new(RefCell::new(qpack::Decoder::new(
            &qpack::Settings::default(),
        )));
        assert_eq!(
            pending.qcsd_abandon_drained_response(),
            Err(Error::InvalidInput)
        );
        assert!(matches!(
            pending.state,
            RecvMessageState::ReadingData { .. }
        ));
        assert!(events.next_event().is_none());

        let (mut blocked, mut events) = response();
        assert!(
            blocked
                .qpack_decoder
                .borrow_mut()
                .decode_header_block(&[0x02, 0x80, 0x10], blocked.stream_id)
                .unwrap()
                .is_none()
        );
        assert!(
            blocked
                .qpack_decoder
                .borrow()
                .is_stream_blocked(blocked.stream_id)
        );
        assert_eq!(
            blocked.qcsd_abandon_drained_response(),
            Err(Error::InvalidInput)
        );
        assert!(matches!(
            blocked.state,
            RecvMessageState::ReadingData { .. }
        ));
        assert!(events.next_event().is_none());
    }
}
