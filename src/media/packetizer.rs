use std::collections::VecDeque;

use async_trait::async_trait;
use bytes::Bytes;

use crate::media::{DynMediaSource, MediaKind, MediaResult, MediaSample, MediaSource};

/// Payloader splits a frame into RTP payloads
pub trait Payloader: Send + Sync {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes>;
}

/// Packetizer wraps a MediaSource and splits frames into packets
pub struct Packetizer {
    source: Box<DynMediaSource>,
    mtu: usize,
    payloader: Box<dyn Payloader>,
    pending: VecDeque<MediaSample>,
}

impl Packetizer {
    pub fn new(source: Box<DynMediaSource>, mtu: usize, payloader: Box<dyn Payloader>) -> Self {
        Self {
            source,
            mtu,
            payloader,
            pending: VecDeque::new(),
        }
    }

    fn packetize_and_push(&mut self, sample: MediaSample) {
        match sample {
            MediaSample::Video(frame) => {
                let payloads = self.payloader.payload(self.mtu, frame.data.clone());
                let count = payloads.len();
                for (i, payload) in payloads.into_iter().enumerate() {
                    let mut f = frame.clone();
                    f.data = payload;
                    f.is_last_packet = i == count - 1;
                    self.pending.push_back(MediaSample::Video(f));
                }
            }
            MediaSample::Audio(_) => {
                self.pending.push_back(sample);
            }
        }
    }
}

#[async_trait]
impl MediaSource for Packetizer {
    fn id(&self) -> &str {
        self.source.id()
    }

    fn kind(&self) -> MediaKind {
        self.source.kind()
    }

    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        loop {
            if let Some(sample) = self.pending.pop_front() {
                return Ok(sample);
            }

            let sample = self.source.next_sample().await?;
            self.packetize_and_push(sample);

            if let Some(s) = self.pending.pop_front() {
                return Ok(s);
            }
        }
    }
}

pub struct Vp8Payloader;

impl Payloader for Vp8Payloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        if data.is_empty() {
            return payloads;
        }

        // Max payload size excluding VP8 payload descriptor (min 1 byte)
        let max_payload_size = mtu - 1;

        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = std::cmp::min(remaining, max_payload_size);

            let mut payload = Vec::with_capacity(chunk_size + 1);

            // VP8 Payload Descriptor
            // S bit is 1 for the first packet of the frame
            // RFC 7741 Section 4.2
            let s_bit = if offset == 0 { 0x10 } else { 0x00 };
            payload.push(s_bit);

            payload.extend_from_slice(&data[offset..offset + chunk_size]);
            payloads.push(Bytes::from(payload));

            offset += chunk_size;
        }

        payloads
    }
}

pub struct SimplePayloader;

impl Payloader for SimplePayloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = std::cmp::min(remaining, mtu);
            payloads.push(data.slice(offset..offset + chunk_size));
            offset += chunk_size;
        }
        payloads
    }
}
