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

        // Every connect/handshake await must race the stop signal, or a worker
        // parked in one on an overwhelmed target won't observe shutdown and the
        // drain force-aborts it after the grace window (5s of overshoot).
        let io = tokio::select! {
            r = target.connect_h2() => match r {
                Ok(io) => io,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    tokio::select! {
                        _ = down.changed() => return,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    continue;
                }
            },
            _ = down.changed() => return,
        };

        let (mut send_req, connection) = tokio::select! {
            r = tokio::time::timeout(super::net::CONNECT_TIMEOUT, h2::client::handshake(io)) => {
                match r {
                    Ok(Ok(pair)) => pair,
                    _ => {
                        metrics.errors.fetch_add(1, Relaxed);
                        continue;
                    }
                }
            }
            _ = down.changed() => return,
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

            // Race the response against shutdown so a silent stream can't pin us.
            let resp = tokio::select! {
                r = resp_fut => r,
                _ = down.changed() => break 'req,
            };
            match resp {
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
