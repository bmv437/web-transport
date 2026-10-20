//! A session given its own `quinn::Runtime` must time things on that runtime's clock.
//!
//! `Runtime::now` lets a runtime supply its own clock, as tokio's paused time or a
//! simulator does, and quinn computes every deadline it passes to `new_timer` from it.
//! A deadline computed from `Instant::now` instead lands in the past of a runtime whose
//! clock runs ahead, so the timer fires at once.

// The server builder needs quinn's tokio runtime, which the test runtime also wraps, and
// the client config needs a crypto provider.
#![cfg(all(feature = "tokio", any(feature = "aws-lc-rs", feature = "ring")))]

use std::{
    future::Future,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use web_transport_proto::ConnectRequest;
use web_transport_quinn::{ServerBuilder, Session};

/// How far [`OffsetRuntime`]'s clock runs ahead of the real one, well past any close timeout.
const OFFSET: Duration = Duration::from_secs(60 * 60);

/// Quinn's tokio runtime with a clock that runs [`OFFSET`] ahead of `Instant::now`.
/// It records every deadline it is asked to time.
#[derive(Debug, Default)]
struct OffsetRuntime {
    deadlines: Mutex<Vec<Instant>>,
}

impl OffsetRuntime {
    fn deadlines(&self) -> Vec<Instant> {
        self.deadlines.lock().unwrap().clone()
    }
}

impl Runtime for OffsetRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.deadlines.lock().unwrap().push(deadline);

        // Move the deadline onto the real clock; one already in this clock's past fires at once.
        let remaining = deadline.saturating_duration_since(self.now());
        TokioRuntime.new_timer(Instant::now() + remaining)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        TokioRuntime.spawn(future)
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        Instant::now() + OFFSET
    }
}

/// With both crypto features enabled, as `--all-features` does, the crate cannot pick a
/// provider for us, so the test installs one.
fn install_crypto_provider() {
    #[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

/// A client session on `runtime`, connected to a server session on quinn's tokio runtime.
async fn pair(runtime: Arc<dyn Runtime>) -> Result<(Session, Session)> {
    install_crypto_provider();

    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KeyPair::serialize_der(
        &signing_key,
    )));

    let mut server = ServerBuilder::new()
        .with_addr((Ipv4Addr::LOCALHOST, 0).into())
        .with_certificate(vec![cert.der().clone()], key)?;
    let addr = server.local_addr()?;

    let server_task = tokio::spawn(async move {
        let request = server.accept().await.context("no connection")?;
        anyhow::Ok(request.ok().await?)
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone())?;

    let provider = web_transport_quinn::crypto::default_provider();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    let conn = endpoint.connect_with(config, addr, "localhost")?.await?;

    let url: url::Url = format!("https://localhost:{}/", addr.port()).parse()?;
    let client = Session::connect_with(conn, ConnectRequest::new(url), runtime).await?;

    let server = server_task.await??;
    Ok((client, server))
}

/// The graceful close bounds its wait for the peer with a timer on the session's
/// runtime, so its deadline has to be ahead of that runtime's clock.
#[tokio::test]
async fn close_deadline_follows_the_runtime_clock() -> Result<()> {
    let runtime = Arc::new(OffsetRuntime::default());
    let (client, _server) = pair(runtime.clone()).await?;

    let before = runtime.now();
    client.close(0, b"bye");
    client.closed().await;

    let deadlines = runtime.deadlines();
    assert!(
        !deadlines.is_empty(),
        "close did not start a timer on the session's runtime"
    );
    for deadline in deadlines {
        assert!(
            deadline > before,
            "the close deadline is {:?} behind the runtime's clock",
            before - deadline
        );
    }

    Ok(())
}
