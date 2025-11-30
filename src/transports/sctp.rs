use crate::transports::dtls::DtlsTransport;
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tracing::{debug, trace, warn};

// DCEP Constants
const DATA_CHANNEL_PPID_DCEP: u32 = 50;
const DATA_CHANNEL_PPID_BINARY: u32 = 53;

const DCEP_TYPE_OPEN: u8 = 0x03;
const DCEP_TYPE_ACK: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct DataChannelOpen {
    pub message_type: u8,
    pub channel_type: u8,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
}

impl DataChannelOpen {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.message_type);
        buf.put_u8(self.channel_type);
        buf.put_u16(self.priority);
        buf.put_u32(self.reliability_parameter);

        let label_bytes = self.label.as_bytes();
        buf.put_u16(label_bytes.len() as u16);

        let protocol_bytes = self.protocol.as_bytes();
        buf.put_u16(protocol_bytes.len() as u16);

        buf.put_slice(label_bytes);
        buf.put_slice(protocol_bytes);

        buf.to_vec()
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        if buf.remaining() < 12 {
            return Err(anyhow::anyhow!("DCEP Open message too short"));
        }

        let message_type = buf.get_u8();
        if message_type != DCEP_TYPE_OPEN {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }

        let channel_type = buf.get_u8();
        let priority = buf.get_u16();
        let reliability_parameter = buf.get_u32();
        let label_len = buf.get_u16() as usize;
        let protocol_len = buf.get_u16() as usize;

        if buf.remaining() < label_len + protocol_len {
            return Err(anyhow::anyhow!("DCEP Open message too short for payload"));
        }

        let label_bytes = buf.split_to(label_len);
        let protocol_bytes = buf.split_to(protocol_len);

        let label = String::from_utf8(label_bytes.to_vec())?;
        let protocol = String::from_utf8(protocol_bytes.to_vec())?;

        Ok(Self {
            message_type,
            channel_type,
            priority,
            reliability_parameter,
            label,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DataChannelAck {
    pub message_type: u8,
}

impl DataChannelAck {
    pub fn marshal(&self) -> Vec<u8> {
        vec![self.message_type]
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("DCEP Ack message too short"));
        }
        let message_type = data[0];
        if message_type != DCEP_TYPE_ACK {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }
        Ok(Self { message_type })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    New,
    Connecting,
    Connected,
    Closed,
}

#[derive(Debug, Clone)]
pub enum DataChannelEvent {
    Open,
    Message(Vec<u8>),
    Close,
}

pub struct DataChannel {
    pub id: u16,
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub negotiated: bool,
    pub state: Mutex<DataChannelState>,
    pub next_ssn: Mutex<u16>,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelState {
    Connecting,
    Open,
    Closing,
    Closed,
}

// SCTP Constants
const SCTP_COMMON_HEADER_SIZE: usize = 12;
const CHUNK_HEADER_SIZE: usize = 4;

// Chunk Types
const CT_DATA: u8 = 0;
const CT_INIT: u8 = 1;
const CT_INIT_ACK: u8 = 2;
const CT_SACK: u8 = 3;
const CT_HEARTBEAT: u8 = 4;
const CT_HEARTBEAT_ACK: u8 = 5;
#[allow(unused)]
const CT_ABORT: u8 = 6;
#[allow(unused)]
const CT_SHUTDOWN: u8 = 7;
#[allow(unused)]
const CT_SHUTDOWN_ACK: u8 = 8;
#[allow(unused)]
const CT_ERROR: u8 = 9;
const CT_COOKIE_ECHO: u8 = 10;
const CT_COOKIE_ACK: u8 = 11;

struct SctpInner {
    dtls_transport: Arc<DtlsTransport>,
    state: Arc<Mutex<SctpState>>,
    data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
    local_port: u16,
    remote_port: u16,
    verification_tag: Mutex<u32>,
    remote_verification_tag: Mutex<u32>,
    next_tsn: Mutex<u32>,
    new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
}

pub struct SctpTransport {
    inner: Arc<SctpInner>,
    close_tx: Arc<tokio::sync::Notify>,
}

impl SctpTransport {
    pub fn new(
        dtls_transport: Arc<DtlsTransport>,
        data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
        local_port: u16,
        remote_port: u16,
        new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
    ) -> (
        Arc<Self>,
        impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let inner = Arc::new(SctpInner {
            dtls_transport,
            state: Arc::new(Mutex::new(SctpState::New)),
            data_channels,
            local_port,
            remote_port,
            verification_tag: Mutex::new(0),
            remote_verification_tag: Mutex::new(0),
            next_tsn: Mutex::new(0),
            new_data_channel_tx,
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        let inner_clone = inner.clone();
        let runner = async move {
            inner_clone.run_loop(close_rx).await;
        };

        (transport, runner)
    }

    pub fn create_data_channel(&self, id: u16, config: DataChannelConfig) -> Arc<DataChannel> {
        let negotiated = config.negotiated.is_some();
        let dc = Arc::new(DataChannel::new(id, config));
        self.inner
            .data_channels
            .lock()
            .unwrap()
            .push(Arc::downgrade(&dc));

        if !negotiated {
            let inner = self.inner.clone();
            let dc_clone = dc.clone();
            tokio::spawn(async move {
                // Wait for SCTP to be connected before sending DCEP OPEN?
                // Or just send it and let it queue?
                // Ideally we should wait.
                // For now, let's just try to send.
                if let Err(e) = inner.send_dcep_open(&dc_clone).await {
                    warn!("Failed to send DCEP OPEN: {}", e);
                }
            });
        } else {
            let state = *self.inner.state.lock().unwrap();
            if state == SctpState::Connected {
                *dc.state.lock().unwrap() = DataChannelState::Open;
                dc.send_event(DataChannelEvent::Open);
            }
        }

        dc
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.inner.send_data(channel_id, data).await
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        self.inner.send_dcep_open(dc).await
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl SctpInner {
    async fn run_loop(&self, close_rx: Arc<tokio::sync::Notify>) {
        *self.state.lock().unwrap() = SctpState::Connecting;
        loop {
            tokio::select! {
                _ = close_rx.notified() => break,
                res = self.dtls_transport.recv() => {
                    match res {
                        Ok(packet) => {
                            if let Err(e) = self.handle_packet(&packet).await {
                                warn!("SCTP handle packet error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("SCTP loop error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        *self.state.lock().unwrap() = SctpState::Closed;

        let channels = self.data_channels.lock().unwrap();
        for weak_dc in channels.iter() {
            if let Some(dc) = weak_dc.upgrade() {
                let mut state = dc.state.lock().unwrap();
                if *state != DataChannelState::Closed {
                    *state = DataChannelState::Closed;
                    drop(state);
                    dc.send_event(DataChannelEvent::Close);
                    dc.close_channel();
                }
            }
        }
    }

    async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        let mut buf = Bytes::copy_from_slice(packet);
        let _src_port = buf.get_u16();
        let _dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let _checksum = buf.get_u32();

        // Verify checksum (TODO)

        while buf.has_remaining() {
            if buf.remaining() < CHUNK_HEADER_SIZE {
                break;
            }
            let chunk_type = buf.get_u8();
            let chunk_flags = buf.get_u8();
            let chunk_length = buf.get_u16() as usize;

            if chunk_length < CHUNK_HEADER_SIZE
                || buf.remaining() < chunk_length - CHUNK_HEADER_SIZE
            {
                break;
            }

            let chunk_value = buf.split_to(chunk_length - CHUNK_HEADER_SIZE);

            // Padding
            let padding = (4 - (chunk_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            match chunk_type {
                CT_INIT => self.handle_init(verification_tag, chunk_value).await?,
                CT_COOKIE_ECHO => self.handle_cookie_echo(chunk_value).await?,
                CT_DATA => self.handle_data(chunk_flags, chunk_value).await?,
                CT_HEARTBEAT => self.handle_heartbeat(chunk_value).await?,
                _ => {
                    trace!("Unhandled SCTP chunk type: {}", chunk_type);
                }
            }
        }
        Ok(())
    }

    async fn handle_init(&self, _remote_tag: u32, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            // Fixed params
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let _a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let _initial_tsn = buf.get_u32();

        *self.remote_verification_tag.lock().unwrap() = initiate_tag;

        // Generate local tag
        let local_tag = random_u32();
        *self.verification_tag.lock().unwrap() = local_tag;

        // Send INIT ACK
        // We need to construct a cookie. For simplicity, we'll just echo back some dummy data.
        let cookie = b"dummy_cookie";

        let mut init_ack_params = BytesMut::new();
        // Initiate Tag
        init_ack_params.put_u32(local_tag);
        // a_rwnd
        init_ack_params.put_u32(128 * 1024);
        // Outbound streams
        init_ack_params.put_u16(10);
        // Inbound streams
        init_ack_params.put_u16(10);
        // Initial TSN
        let initial_tsn = random_u32();
        *self.next_tsn.lock().unwrap() = initial_tsn;
        init_ack_params.put_u32(initial_tsn);

        // State Cookie Parameter (Type 7)
        init_ack_params.put_u16(7);
        init_ack_params.put_u16(4 + cookie.len() as u16);
        init_ack_params.put_slice(cookie);
        // Padding for cookie
        let padding = (4 - (cookie.len() % 4)) % 4;
        for _ in 0..padding {
            init_ack_params.put_u8(0);
        }

        self.send_chunk(CT_INIT_ACK, 0, init_ack_params.freeze(), initiate_tag)
            .await?;
        Ok(())
    }

    async fn handle_cookie_echo(&self, _chunk: Bytes) -> Result<()> {
        // Send COOKIE ACK
        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_COOKIE_ACK, 0, Bytes::new(), tag).await?;

        *self.state.lock().unwrap() = SctpState::Connected;

        let channels_to_process = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut to_process = Vec::new();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    to_process.push(dc);
                    true
                } else {
                    false
                }
            });
            to_process
        };

        for dc in channels_to_process {
            if dc.negotiated {
                *dc.state.lock().unwrap() = DataChannelState::Open;
                dc.send_event(DataChannelEvent::Open);
            } else {
                let state = *dc.state.lock().unwrap();
                if state == DataChannelState::Connecting {
                    if let Err(e) = self.send_dcep_open(&dc).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_heartbeat(&self, chunk: Bytes) -> Result<()> {
        // Send HEARTBEAT ACK with same info
        // ...

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_HEARTBEAT_ACK, 0, chunk, tag).await?;
        Ok(())
    }

    async fn handle_data(&self, _flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 12 {
            return Ok(());
        }
        let tsn = buf.get_u32();
        let stream_id = buf.get_u16();
        let _stream_seq = buf.get_u16();
        let payload_proto = buf.get_u32();

        let user_data = buf;

        // Send SACK (Simplified: just ack this TSN)
        let mut sack = BytesMut::new();
        sack.put_u32(tsn); // Cumulative TSN Ack
        sack.put_u32(1024 * 1024); // a_rwnd
        sack.put_u16(0); // Number of Gap Ack Blocks
        sack.put_u16(0); // Number of Duplicate TSNs

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_SACK, 0, sack.freeze(), tag).await?;

        if payload_proto == DATA_CHANNEL_PPID_DCEP {
            self.handle_dcep(stream_id, user_data).await?;
            return Ok(());
        }

        let mut channels = self.data_channels.lock().unwrap();
        let mut found_dc = None;
        channels.retain(|weak_dc| {
            if let Some(dc) = weak_dc.upgrade() {
                if dc.id == stream_id {
                    found_dc = Some(dc);
                }
                true
            } else {
                false
            }
        });

        if let Some(dc) = found_dc {
            dc.send_event(DataChannelEvent::Message(user_data.to_vec()));
        }

        Ok(())
    }

    async fn handle_dcep(&self, stream_id: u16, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let msg_type = data[0];
        match msg_type {
            DCEP_TYPE_OPEN => {
                let open = DataChannelOpen::unmarshal(&data)?;
                trace!("Received DCEP OPEN: {:?}", open);

                let mut found = false;
                {
                    let channels = self.data_channels.lock().unwrap();
                    for weak_dc in channels.iter() {
                        if let Some(dc) = weak_dc.upgrade() {
                            if dc.id == stream_id {
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if !found {
                    // Create new channel
                    let config = DataChannelConfig {
                        label: open.label.clone(),
                        protocol: open.protocol,
                        ordered: (open.channel_type & 0x80) == 0,
                        max_retransmits: if (open.channel_type & 0x03) == 0x01
                            || (open.channel_type & 0x03) == 0x81
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        max_packet_life_time: if (open.channel_type & 0x03) == 0x02
                            || (open.channel_type & 0x03) == 0x82
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        negotiated: None,
                    };

                    let dc = Arc::new(DataChannel::new(stream_id, config));
                    *dc.state.lock().unwrap() = DataChannelState::Open;

                    {
                        let mut channels = self.data_channels.lock().unwrap();
                        channels.push(Arc::downgrade(&dc));
                    }

                    if let Some(tx) = &self.new_data_channel_tx {
                        let _ = tx.send(dc.clone());
                    } else {
                        debug!(
                            "New DataChannel created from DCEP: id={} label={} (no listener)",
                            stream_id, open.label
                        );
                    }
                }

                // Send ACK
                self.send_dcep_ack(stream_id).await?;
            }
            DCEP_TYPE_ACK => {
                trace!("Received DCEP ACK for stream {}", stream_id);
                let channels = self.data_channels.lock().unwrap();
                for weak_dc in channels.iter() {
                    if let Some(dc) = weak_dc.upgrade() {
                        if dc.id == stream_id {
                            let mut state = dc.state.lock().unwrap();
                            if *state == DataChannelState::Connecting {
                                *state = DataChannelState::Open;
                                dc.send_event(DataChannelEvent::Open);
                            }
                            break;
                        }
                    }
                }
            }
            _ => {
                debug!("Unknown DCEP message type: {}", msg_type);
            }
        }
        Ok(())
    }

    async fn send_chunk(
        &self,
        type_: u8,
        flags: u8,
        value: Bytes,
        verification_tag: u32,
    ) -> Result<()> {
        let mut packet = BytesMut::new();

        // Common Header
        packet.put_u16(self.local_port);
        packet.put_u16(self.remote_port);
        packet.put_u32(verification_tag);
        packet.put_u32(0); // Checksum placeholder

        // Chunk
        packet.put_u8(type_);
        packet.put_u8(flags);
        packet.put_u16((CHUNK_HEADER_SIZE + value.len()) as u16);
        packet.put_slice(&value);

        // Padding
        let padding = (4 - (value.len() % 4)) % 4;
        for _ in 0..padding {
            packet.put_u8(0);
        }

        // Calculate Checksum (CRC32c)
        let checksum = crc32c::crc32c(&packet);

        let mut packet_bytes = packet.to_vec();
        let checksum_bytes = checksum.to_le_bytes();

        packet_bytes[8] = checksum_bytes[0];
        packet_bytes[9] = checksum_bytes[1];
        packet_bytes[10] = checksum_bytes[2];
        packet_bytes[11] = checksum_bytes[3];

        self.dtls_transport.send(&packet_bytes).await
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_BINARY, data)
            .await
    }

    pub async fn send_data_raw(&self, channel_id: u16, ppid: u32, data: &[u8]) -> Result<()> {
        // Wrap in DATA chunk
        let mut payload = BytesMut::new();

        let tsn = {
            let mut tsn_guard = self.next_tsn.lock().unwrap();
            let tsn = *tsn_guard;
            *tsn_guard = tsn.wrapping_add(1);
            tsn
        };

        let ssn = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut found_dc = None;
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    if dc.id == channel_id {
                        found_dc = Some(dc);
                    }
                    true
                } else {
                    false
                }
            });

            if let Some(dc) = found_dc {
                let mut ssn_guard = dc.next_ssn.lock().unwrap();
                let ssn = *ssn_guard;
                *ssn_guard = ssn.wrapping_add(1);
                ssn
            } else {
                0
            }
        };

        payload.put_u32(tsn); // TSN
        payload.put_u16(channel_id); // Stream ID
        payload.put_u16(ssn); // Stream Seq
        payload.put_u32(ppid); // PPID
        payload.put_slice(data);

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_DATA, 0x03, payload.freeze(), tag).await // 0x03 = B(egin) | E(nd)
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        let channel_type = if dc.ordered {
            if dc.max_retransmits.is_some() {
                0x01 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT
            } else if dc.max_packet_life_time.is_some() {
                0x02 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED
            } else {
                0x00 // DATA_CHANNEL_RELIABLE
            }
        } else {
            if dc.max_retransmits.is_some() {
                0x81 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED
            } else if dc.max_packet_life_time.is_some() {
                0x82 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED
            } else {
                0x80 // DATA_CHANNEL_RELIABLE_UNORDERED
            }
        };

        let reliability_parameter = if let Some(r) = dc.max_retransmits {
            r as u32
        } else if let Some(t) = dc.max_packet_life_time {
            t as u32
        } else {
            0
        };

        let open = DataChannelOpen {
            message_type: DCEP_TYPE_OPEN,
            channel_type,
            priority: 0,
            reliability_parameter,
            label: dc.label.clone(),
            protocol: dc.protocol.clone(),
        };

        let payload = open.marshal();
        self.send_data_raw(dc.id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }

    pub async fn send_dcep_ack(&self, channel_id: u16) -> Result<()> {
        let ack = DataChannelAck {
            message_type: DCEP_TYPE_ACK,
        };
        let payload = ack.marshal();
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct DataChannelConfig {
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub negotiated: Option<u16>,
}

impl DataChannel {
    pub fn new(id: u16, config: DataChannelConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            label: config.label,
            protocol: config.protocol,
            ordered: config.ordered,
            max_retransmits: config.max_retransmits,
            max_packet_life_time: config.max_packet_life_time,
            negotiated: config.negotiated.is_some(),
            state: Mutex::new(DataChannelState::Connecting),
            next_ssn: Mutex::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
        }
    }

    pub async fn recv(&self) -> Option<DataChannelEvent> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }

    pub(crate) fn send_event(&self, event: DataChannelEvent) {
        if let Some(tx) = &*self.tx.lock().unwrap() {
            let _ = tx.send(event);
        }
    }

    pub(crate) fn close_channel(&self) {
        *self.tx.lock().unwrap() = None;
    }
}
