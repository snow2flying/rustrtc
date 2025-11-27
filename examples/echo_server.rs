use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::PeerConnection;
use rustrtc::media::{self, MediaKind as MediaStreamKind, MediaStreamTrack};
use rustrtc::{RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use webrtc::track::track_local::TrackLocalWriter;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::{api::APIBuilder, rtp_transceiver::rtp_codec::RTCRtpCodecCapability};
use webrtc::{api::media_engine::MediaEngine, track::track_remote::TrackRemote};
use webrtc::{
    api::{interceptor_registry::register_default_interceptors, media_engine::MIME_TYPE_VP8},
    rtp_transceiver::RTCRtpTransceiver,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=debug")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/offer", post(offer))
        .nest_service("/static", ServeDir::new("examples/static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
    #[allow(unused)]
    r#type: String,
    #[serde(default)]
    backend: String,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
    #[serde(rename = "type")]
    type_: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer with backend: {}", payload.backend);

    if payload.backend == "webrtc-rs" {
        handle_webrtc_rs_offer(payload).await
    } else {
        handle_rustrtc_offer(payload).await
    }
}

async fn handle_webrtc_rs_offer(payload: OfferRequest) -> Json<OfferResponse> {
    // Create a MediaEngine object to configure the supported codec
    let mut m = MediaEngine::default();
    m.register_default_codecs().unwrap();

    let mut registry = webrtc::interceptor::registry::Registry::new();
    registry = register_default_interceptors(registry, &mut m).unwrap();

    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let config = RTCConfiguration {
        ..Default::default()
    };

    let pc = Arc::new(api.new_peer_connection(config).await.unwrap());

    // Data Channel Echo
    let dc = pc.create_data_channel("echo", None).await.unwrap();
    let dc_clone = dc.clone();
    let codec = RTCRtpCodecCapability {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        ..Default::default()
    };
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        codec,
        "id".to_string(),
        "stream_id".to_string(),
    ));
    pc.add_track(video_track.clone())
        .await
        .expect("add video track");
    pc.on_track(Box::new(
        move |track: Arc<TrackRemote>,
              _receiver: Arc<RTCRtpReceiver>,
              _transceiver: Arc<RTCRtpTransceiver>| {
            info!("on_track received: {}", track.codec().capability.mime_type,);
            let video_track = video_track.clone();
            Box::pin(async move {
                loop {
                    match track.read_rtp().await {
                        Ok((packet, _)) => {
                            if let Err(_) = video_track.write_rtp(&packet).await {
                                break;
                            }
                        }
                        Err(e) => {
                            info!("track read error: {}", e);
                            break;
                        }
                    }
                }
            })
        },
    ));
    dc.on_open(Box::new(move || {
        info!("Data channel 'echo' opened");
        let dc2 = dc_clone.clone();
        dc_clone.on_message(Box::new(
            move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
                let msg_data = String::from_utf8_lossy(&msg.data);
                info!("Received message: {:?}", msg_data);
                let dc3 = dc2.clone();
                let data = msg.data.clone();
                Box::pin(async move {
                    if let Err(e) = dc3.send(&data).await {
                        warn!("Failed to send data: {}", e);
                    } else {
                        info!("Sent echo");
                    }
                })
            },
        ));
        Box::pin(async {})
    }));

    // Set Remote Description
    let desc = RTCSessionDescription::offer(payload.sdp.clone()).unwrap();
    pc.set_remote_description(desc).await.unwrap();

    // Create Answer
    let answer = pc.create_answer(None).await.unwrap();

    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(answer).await.unwrap();
    let _ = gather_complete.recv().await;

    let answer = pc.local_description().await.unwrap();

    Json(OfferResponse {
        sdp: answer.sdp,
        type_: "answer".to_string(),
    })
}
async fn handle_rustrtc_offer(payload: OfferRequest) -> Json<OfferResponse> {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Create DataChannel (negotiated id=0)
    let dc = pc.create_data_channel("echo").await.unwrap();

    // Setup echo
    let pc_clone = pc.clone();
    let dc_clone = dc.clone();

    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    info!("Received message: {:?}", String::from_utf8_lossy(&data));
                    let pc = pc_clone.clone();
                    tokio::spawn(async move {
                        // Echo back
                        if let Err(e) = pc.send_data(0, &data).await {
                            warn!("Failed to send data: {}", e);
                        } else {
                            info!("Sent echo");
                        }
                    });
                }
                rustrtc::transports::sctp::DataChannelEvent::Open => {
                    info!("Data channel opened");
                }
                rustrtc::transports::sctp::DataChannelEvent::Close => {
                    info!("Data channel closed");
                    break;
                }
            }
        }
    });

    // Handle SDP
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    pc.set_remote_description(offer_sdp).await.unwrap();

    configure_rustrtc_video_echo(&pc).await;

    // Create answer and wait for gathering
    let _ = pc.create_answer().await.unwrap();

    // Wait for gathering to complete
    loop {
        if pc.ice_transport().gather_state().await
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).await.unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}

static VIDEO_SSRC_COUNTER: AtomicU32 = AtomicU32::new(0x0099_0001);

async fn configure_rustrtc_video_echo(pc: &PeerConnection) {
    let transceivers = pc.get_transceivers().await;
    for transceiver in transceivers {
        if transceiver.kind() != rustrtc::MediaKind::Video {
            continue;
        }

        transceiver
            .set_direction(rustrtc::TransceiverDirection::SendRecv)
            .await;

        let receiver = transceiver.receiver.lock().await.clone();
        let Some(receiver) = receiver else {
            warn!("Video transceiver {} missing receiver", transceiver.id());
            continue;
        };

        let incoming_track = receiver.track();
        let (sample_source, outgoing_track) = media::sample_track(MediaStreamKind::Video, 120);

        let sender = Arc::new(rustrtc::peer_connection::RtpSender::new(
            outgoing_track.clone(),
            next_video_ssrc(),
        ));
        *transceiver.sender.lock().await = Some(sender);

        tokio::spawn(async move {
            loop {
                match incoming_track.recv().await {
                    Ok(sample) => {
                        if let Err(err) = sample_source.send(sample).await {
                            warn!("Video echo forwarder stopped: {}", err);
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("Video ingress track ended: {}", err);
                        break;
                    }
                }
            }
        });

        info!(
            "Configured RustRTC video echo on transceiver {}",
            transceiver.id()
        );
    }
}

fn next_video_ssrc() -> u32 {
    VIDEO_SSRC_COUNTER.fetch_add(1, Ordering::Relaxed)
}
