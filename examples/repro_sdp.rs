use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};

#[tokio::main]
async fn main() {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::WebRtc;

    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    pc.create_data_channel("test", None).unwrap();

    let offer = pc.create_offer().unwrap();
    println!("SDP:\n{}", offer.to_sdp_string());
}
