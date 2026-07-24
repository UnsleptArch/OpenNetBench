//! HTTP/2 request flood worker (L7).
//!
//! Unlike rapid-reset, this *completes* requests: it opens many streams on one
//! multiplexed h2 connection, awaits each response, and drains the body. It
//! stresses the full request path (routing, handlers) over HTTP/2's cheap
//! stream multiplexing. Latency to response headers feeds the collapse curve.
//! Requires TLS with ALPN `h2`.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        let conn_task = tokio::spawn(async move { let _ = connection.await; });

        'req: loop {
            if *down.borrow() || !gov.active(idx) {
                break 'req;
            }
            send_req = match send_req.ready().await {
                Ok(s) => s,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    break 'req;
                }
            };
            let Ok(request) = http::Request::builder()
                .method(http::Method::GET)
                .uri(&uri)
                .body(())
            else {
                break 'req;
            };

            let t0 = Instant::now();
            metrics.requests_sent.fetch_add(1, Relaxed);
            let (resp_fut, _send) = match send_req.send_request(request, true) {
                Ok(pair) => pair,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    break 'req;
                }
            };

            match resp_fut.await {
                Ok(resp) => {
                    metrics.record_latency(t0.elapsed());
                    metrics.record_status(resp.status().as_u16());
                    metrics.responses_ok.fetch_add(1, Relaxed);
                    // Drain the body, returning flow-control capacity as we go.
                    let mut body = resp.into_body();
                    while let Some(chunk) = body.data().await {
                        match chunk {
                            Ok(bytes) => {
                                let _ = body.flow_control().release_capacity(bytes.len());
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                }
            }
        }
        conn_task.abort();
    }
}
