use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use color_eyre::eyre::{Context, eyre};
use fast_socks5::Socks5Command;
use fast_socks5::server::{Socks5ServerProtocol, transfer};
use rand::seq::IndexedRandom;
use russh::client;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandproxy::{ConfigProxy, ConfigReverseProxy};
use tokio::net::TcpListener;
use tokio::pin;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tracing::{debug, error, info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
struct Cli {
    #[clap(long, short)]
    pub(crate) config: PathBuf,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // Setup
    color_eyre::install()?;
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
                .with_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;

    // Read config
    let config: sandproxy::Config = toml::from_slice(
        &std::fs::read(cli.config).wrap_err_with(|| "Couldn't find configuration")?,
    )
    .wrap_err_with(|| "Invalid configuration")?;

    let sessions = Arc::new(Mutex::new(vec![]));

    // Serve SOCKS5 server
    let listen_addr = SocketAddr::new(
        config
            .address
            .unwrap_or(std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
        config.port,
    );
    let listener = TcpListener::bind(listen_addr)
        .await
        .wrap_err_with(|| "Failed to bind to provided address and port")?;
    info!("Listening on {}", listen_addr);
    let sessions_clone = Arc::clone(&sessions);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    let session: Arc<AsyncMutex<client::Handle<ProxyClient>>> = Arc::clone(
                        sessions_clone
                            .lock()
                            .unwrap()
                            .choose(&mut rand::rng())
                            .expect("Proxy sessions shouldn't be empty"),
                    );
                    let fut = async move {
                        let (proto, cmd, target_addr) =
                            Socks5ServerProtocol::accept_no_auth(socket)
                                .await?
                                .read_command()
                                .await?;
                        if let Socks5Command::TCPConnect = cmd {
                            let (host_to_connect, port_to_connect) =
                                target_addr.into_string_and_port();
                            let channel = session
                                .lock()
                                .await
                                .channel_open_direct_tcpip(
                                    host_to_connect,
                                    port_to_connect.into(),
                                    addr.ip().to_canonical().to_string(),
                                    addr.port().into(),
                                )
                                .await
                                .wrap_err_with(|| "Failed to open TCP/IP forwarding")?;
                            let mut socket = proto
                                .reply_success(std::net::SocketAddr::new(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                                    0,
                                ))
                                .await?;
                            transfer(&mut socket, channel.into_stream()).await;
                        } else {
                            warn!(?cmd, "Unsupported SOCKS5 command")
                        }
                        Ok::<_, color_eyre::Report>(())
                    };
                    tokio::spawn(async move {
                        if let Err(error) = fut.await {
                            error!(%error, "Failed to run task");
                        }
                    });
                }
                Err(error) => error!(%error, "Failed to accept TCP connection"),
            }
        }
    });

    let (reverse_proxy_tx, mut reverse_proxy_rx) = mpsc::unbounded_channel();
    let (proxy_tx, mut proxy_rx) = mpsc::unbounded_channel();
    for account in config.accounts {
        let key = Arc::new(
            load_secret_key(&account.private_key_path, None)
                .wrap_err_with(|| "Missing secret key file")?,
        );

        // Create Sandhole clients
        for reverse_proxy in account.reverse_proxies {
            let ssh_client = SshClient {
                tx: reverse_proxy_tx.clone(),
                data: Some(reverse_proxy.clone()),
            };
            let mut session = client::connect(
                Default::default(),
                (reverse_proxy.host.as_str(), reverse_proxy.port),
                ssh_client,
            )
            .await
            .wrap_err_with(|| "Failed to connect to SSH server")?;
            if !session
                .authenticate_publickey(
                    "sandproxy",
                    PrivateKeyWithHashAlg::new(
                        Arc::clone(&key),
                        session
                            .best_supported_rsa_hash()
                            .await
                            .wrap_err_with(|| "Failed to get best supported RSA hash")?
                            .flatten(),
                    ),
                )
                .await
                .wrap_err_with(|| "SSH authentication failed")?
                .success()
            {
                return Err(eyre!("Sandhole authentication failed"));
            }

            // Create proxy clients
            for proxy in reverse_proxy.proxies {
                let channel = session
                    .channel_open_direct_tcpip(&proxy.alias.0, proxy.alias.1.into(), "::1", 12345)
                    .await
                    .wrap_err_with(|| "Local forwarding failed")?;
                let socket = channel.into_stream();
                let proxy_client = ProxyClient {
                    tx: proxy_tx.clone(),
                    data: Some(proxy.clone()),
                };
                let mut proxy_session =
                    client::connect_stream(Default::default(), socket, proxy_client)
                        .await
                        .wrap_err_with(|| "Failed to connect to proxied SSH server")?;
                if !proxy_session
                    .authenticate_publickey(
                        &proxy.user,
                        PrivateKeyWithHashAlg::new(
                            Arc::clone(&key),
                            proxy_session
                                .best_supported_rsa_hash()
                                .await
                                .wrap_err_with(|| "Failed to get best supported RSA hash")?
                                .flatten(),
                        ),
                    )
                    .await
                    .wrap_err_with(|| "SSH authentication failed")?
                    .success()
                {
                    return Err(eyre!("Proxy authentication failed"));
                }
                let proxy_session = Arc::new(AsyncMutex::new(proxy_session));
                sessions.lock().unwrap().push(proxy_session);
            }
        }
    }
    if sessions.lock().unwrap().is_empty() {
        return Err(eyre!("No sessions available for proxying"));
    }
    pin! {
        let signal_handler = wait_for_signal();
    }
    loop {
        tokio::select! {
            _ = &mut signal_handler => {
                break Err(eyre!("Terminated by signal"));
            }
            reverse_proxy = reverse_proxy_rx.recv() => {
                let Some(reverse_proxy) = reverse_proxy else {
                    break Err(eyre!("Channel closed unexpectedly"));
                };
                // TODO: Replace reverse proxy and children
            }
            proxy = proxy_rx.recv() => {
                let Some(proxy) = proxy else {
                    break Err(eyre!("Channel closed unexpectedly"));
                };
                // TODO: Replace proxy
            }
        }
    }
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
    let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = signal_terminate.recv() => debug!("Received SIGTERM."),
        _ = signal_interrupt.recv() => debug!("Received SIGINT."),
    };
}

#[cfg(windows)]
async fn wait_for_signal() {
    use tokio::signal::windows;

    let mut signal_c = windows::ctrl_c().unwrap();
    let mut signal_break = windows::ctrl_break().unwrap();
    let mut signal_close = windows::ctrl_close().unwrap();
    let mut signal_shutdown = windows::ctrl_shutdown().unwrap();

    tokio::select! {
        _ = signal_c.recv() => debug!("Received CTRL_C."),
        _ = signal_break.recv() => debug!("Received CTRL_BREAK."),
        _ = signal_close.recv() => debug!("Received CTRL_CLOSE."),
        _ = signal_shutdown.recv() => debug!("Received CTRL_SHUTDOWN."),
    };
}

struct SshClient {
    tx: UnboundedSender<ConfigReverseProxy>,
    data: Option<ConfigReverseProxy>,
}

impl client::Handler for SshClient {
    type Error = color_eyre::Report;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .data
            .as_ref()
            .and_then(|data| data.server_key_fingerprint.as_ref())
            .is_none_or(|fingerprint| key.fingerprint(fingerprint.0.algorithm()) == fingerprint.0))
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        debug!(?reason, "SSH client disconnected");
        if let Some(data) = self.data.take() {
            self.tx.send(data)?;
        }
        Ok(())
    }
}

struct ProxyClient {
    tx: UnboundedSender<ConfigProxy>,
    data: Option<ConfigProxy>,
}

impl client::Handler for ProxyClient {
    type Error = color_eyre::Report;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .data
            .as_ref()
            .and_then(|data| data.server_key_fingerprint.as_ref())
            .is_none_or(|fingerprint| key.fingerprint(fingerprint.0.algorithm()) == fingerprint.0))
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        debug!(?reason, "SSH proxy client disconnected");
        if let Some(data) = self.data.take() {
            self.tx.send(data)?;
        }
        Ok(())
    }
}
