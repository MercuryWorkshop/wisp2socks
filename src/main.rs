use bytes::Bytes;
use clap::Parser;
use fastwebsockets::{handshake, FragmentCollectorRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Request, Uri,
};
use hyper_util::rt::TokioIo;
use socks5_proto::{Address, Reply};
use socks5_server::{
    auth::NoAuth, connection::state::NeedAuthenticate, Command, IncomingConnection, Server,
};
use std::{error::Error, fmt::Display, future::Future, net::SocketAddr, sync::Arc};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt, WriteHalf},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::{native_tls, TlsConnector};
use tokio_util::either::Either;
use wisp_mux::{ClientMux, StreamType};

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::spawn(fut);
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
enum Wisp2SocksError {
    UriHasNoScheme,
    UriHasInvalidScheme,
    UriHasNoHost,
}

impl Display for Wisp2SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UriHasNoScheme => write!(f, "URI has no scheme"),
            Self::UriHasInvalidScheme => write!(f, "URI has invalid scheme"),
            Self::UriHasNoHost => write!(f, "URI has no host"),
        }
    }
}

impl Error for Wisp2SocksError {}

/// Wisp to SOCKS5.
#[derive(Debug, Parser)]
struct Cli {
    /// WebSocket URL of Wisp server
    #[arg(short, long, value_name = "URL")]
    wisp: Uri,
    /// Address to listen for SOCKS server
    #[arg(short, long, value_name = "ADDRESS")]
    socks: SocketAddr,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let opts = Cli::parse();
    let listener = TcpListener::bind(opts.socks).await?;
    let auth = Arc::new(NoAuth);

    let tls = match opts
        .wisp
        .scheme_str()
        .ok_or(Wisp2SocksError::UriHasNoScheme)?
    {
        "wss" => Ok(true),
        "ws" => Ok(false),
        _ => Err(Box::new(Wisp2SocksError::UriHasInvalidScheme)),
    }?;

    let wisp_host = opts
        .wisp
        .host()
        .ok_or(Wisp2SocksError::UriHasNoHost)?
        .to_string();
    let wisp_port = opts.wisp.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let wisp_url = opts.wisp.path().to_string();

    let server = Server::new(listener, auth);

    while let Ok((conn, _)) = server.accept().await {
        let wisp_host = wisp_host.clone();
        let wisp_url = wisp_url.clone();
        tokio::spawn(async move {
            println!(
                "connection handled: {:?}",
                handle_conn(conn, tls, wisp_host, wisp_port, wisp_url).await
            )
        });
    }

    Ok(())
}

async fn connect_to_wisp(
    tls: bool,
    wisp_host: String,
    wisp_port: u16,
    wisp_url: String,
) -> Result<ClientMux<WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>>, Box<dyn Error + Send + Sync>> {
    let wisp = format!("{}:{}", wisp_host, wisp_port);
    let socket = TcpStream::connect(&wisp).await?;
    let socket = if tls {
        let cx = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
        Either::Left(cx.connect(&wisp_host, socket).await?)
    } else {
        Either::Right(socket)
    };

    let req = Request::builder()
        .method("GET")
        .uri(wisp_url)
        .header("Host", wisp_host)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .body(Empty::<Bytes>::new())?;

    let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

    let (rx, tx) = ws.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    let (mux, fut) = ClientMux::new(rx, tx).await?;

    tokio::spawn(fut);
    Ok(mux)
}

async fn handle_conn(
    conn: IncomingConnection<(), NeedAuthenticate>,
    tls: bool,
    wisp_host: String,
    wisp_port: u16,
    wisp_url: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = match conn.authenticate().await {
        Ok((conn, _)) => conn,
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(Box::new(err));
        }
    };

    let mux = match connect_to_wisp(tls, wisp_host, wisp_port, wisp_url).await {
        Ok(mux) => mux,
        Err(err) => {
            let _ = conn.into_inner().shutdown().await;
            return Err(err);
        }
    };

    match conn.wait().await {
        Ok(Command::Associate(associate, _)) => {
            let replied = associate
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Box::new(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Bind(bind, _)) => {
            let replied = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Box::new(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Connect(connect, addr)) => {
            let target = match addr {
                Address::DomainAddress(domain, port) => {
                    mux.client_new_stream(
                        StreamType::Tcp,
                        String::from_utf8_lossy(&domain).into(),
                        port,
                    )
                    .await
                }
                Address::SocketAddress(addr) => {
                    mux.client_new_stream(StreamType::Tcp, addr.ip().to_string(), addr.port())
                        .await
                }
            };

            if let Ok(target) = target {
                let mut target = target.into_io().into_asyncrw();
                let replied = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await;

                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(Box::new(err));
                    }
                };

                let res = copy_bidirectional(&mut target, &mut conn).await;
                let _ = conn.shutdown().await;
                let _ = target.shutdown().await;

                res?;
            } else {
                let replied = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await;

                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(Box::new(err));
                    }
                };

                let _ = conn.shutdown().await;
            }
        }
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(Box::new(err));
        }
    }

    Ok(())
}
