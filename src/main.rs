use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use color_eyre::eyre::{Context, eyre};
use fast_socks5::Socks5Command;
use fast_socks5::server::{Socks5ServerProtocol, transfer};
use russh::client;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
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
    let key = Arc::new(
        load_secret_key(&config.accounts[0].private_key_path, None)
            .wrap_err_with(|| "Missing secret key file")?,
    );

    // Create Sandhole client
    let ssh_client = SshClient;
    let mut session = client::connect(
        Default::default(),
        (
            config.accounts[0].reverse_proxies[0].host.as_str(),
            config.accounts[0].reverse_proxies[0].port,
        ),
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
    let channel = session
        .channel_open_direct_tcpip(
            &config.accounts[0].reverse_proxies[0].proxies[0].alias.0,
            config.accounts[0].reverse_proxies[0].proxies[0]
                .alias
                .1
                .into(),
            "::1",
            12345,
        )
        .await
        .wrap_err_with(|| "Local forwarding failed")?;
    let socket = channel.into_stream();

    // Create proxy client
    let proxy_client = ProxyClient;
    let mut proxy_session = client::connect_stream(Default::default(), socket, proxy_client)
        .await
        .wrap_err_with(|| "Failed to connect to proxied SSH server")?;
    if !proxy_session
        .authenticate_publickey(
            &config.accounts[0].reverse_proxies[0].proxies[0].user,
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
    let proxy_session = Arc::new(Mutex::new(proxy_session));

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
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let session = Arc::clone(&proxy_session);
                let fut = async move {
                    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
                        .await?
                        .read_command()
                        .await?;
                    if let Socks5Command::TCPConnect = cmd {
                        let (host_to_connect, port_to_connect) = target_addr.into_string_and_port();
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
}

struct SshClient;

impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct ProxyClient;

impl client::Handler for ProxyClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
