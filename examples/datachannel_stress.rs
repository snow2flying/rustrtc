use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=info")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/offer", post(offer))
        .nest_service("/static", ServeDir::new("examples/static"));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/datachannel_stress.html"))
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
    #[serde(default)]
    ping_pong: bool,
    chunk_count: Option<usize>,
    chunk_size: Option<usize>,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    let config = RtcConfiguration::default();
    let pc = Arc::new(PeerConnection::new(config));
    let use_ping_pong = payload.ping_pong;

    pc.set_remote_description(offer_sdp).await.unwrap();

    // Create answer
    let _ = pc.create_answer().unwrap();

    // Wait for gathering to complete (simple approach for example)
    pc.wait_for_gathering_complete().await;

    let answer = pc.create_answer().unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    let pc_clone = pc.clone();
    let chunk_count = payload.chunk_count.unwrap_or(256);
    let chunk_size = payload.chunk_size.unwrap_or(62208);

    tokio::spawn(async move {
        while let Some(ev) = pc_clone.recv().await {
            match ev {
                PeerConnectionEvent::DataChannel(dc) => {
                    info!("Received DataChannel: {} label: {}", dc.id, dc.label);
                    let channel_id = dc.id;
                    let pc_sender = pc_clone.clone();
                    let dc_clone = dc.clone();

                    tokio::spawn(async move {
                        if use_ping_pong {
                            info!("Waiting for ping...");
                            while let Some(event) = dc_clone.recv().await {
                                match event {
                                    rustrtc::DataChannelEvent::Message(msg) => {
                                        if msg == "ping".as_bytes() {
                                            info!("Received ping, sending pong...");
                                            if let Err(e) =
                                                pc_sender.send_data(channel_id, b"pong").await
                                            {
                                                info!("Failed to send pong: {}", e);
                                                return;
                                            }

                                            // Give client a moment to process pong
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                100,
                                            ))
                                            .await;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            info!("Ping-pong disabled, waiting 1s before sending...");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }

                        info!(
                            "Starting to send data... chunk_count={} chunk_size={}",
                            chunk_count, chunk_size
                        );
                        let data = vec![0u8; chunk_size];
                        for i in 0..chunk_count {
                            if let Err(e) = pc_sender.send_data(channel_id, &data).await {
                                info!("Failed to send data packet {}: {}", i, e);
                                break;
                            }
                        }
                        info!("Finished sending data");
                        // Keep channel open for a bit to ensure delivery
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    });
                }
                _ => {}
            }
        }
    });

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
    })
}
