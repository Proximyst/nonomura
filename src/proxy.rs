use crate::{ping::Ping, prelude::*, Routes};
use bytes::{Buf as _, BytesMut};
use futures::FutureExt as _;
use snafu::ensure;
use std::net::{IpAddr, Ipv6Addr};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

#[derive(Debug, Snafu)]
pub enum ProxyError {
    #[snafu(display("unexpected end-of-file"))]
    UnexpectedEof,

    Io {
        source: tokio::io::Error,
    },
    PingDecode {
        source: crate::ping::Error,
    },
    DestinationConnectionUnattainable {
        source: tokio::io::Error,
    },
    ProxyProtocolEncoding {
        source: proxy_protocol::EncodeError,
    },

    Libc,
}

type Result<T, E = ProxyError> = std::result::Result<T, E>;

/// If a handshake begins with this monstrosity, it's a pre-rewrite ping and
/// must be handled accordingly.
const LEGACY_PING_PREFIX: [u8; 3] = [0xFE, 0x01, 0xFA];

pub async fn proxy(stream: &mut TcpStream, routes: Routes) -> Result<()> {
    // Alright, new Minecraft connection. It will now send the first packet:
    // the handshake. This will be used to find out the hostname wanted. If the
    // client is on a legacy client, this should be detectable by its first
    // bytes sent, else, it's a post-rewrite ping and should have it handled
    // appropriately.
    //
    // If it's a legacy ping, remember to add a last \0 and the IP they
    // connected from as a 4 byte integer. If it's not, read the handshake
    // data as it should be read, and add ":<client_ip>" on the hostname.
    // I'd rather truncate hostname than truncate IP.

    stream.set_nodelay(true).context(Io)?;

    let addr = stream.peer_addr().context(Io)?;

    let mut buf = BytesMut::with_capacity(512);
    stream.read_buf(&mut buf).await.context(Io)?;
    ensure!(buf.remaining() >= 3, UnexpectedEof);
    let mut prefix = [0u8; 3];
    buf.clone().copy_to_slice(&mut prefix); // Clone is cheap
    let legacy = prefix == LEGACY_PING_PREFIX;

    // Ensure we have enough for next up.
    stream.read_buf(&mut buf).await.context(Io)?;

    // We know if it's legacy now, and thus know how to read the hostname.
    let mut ping_buf = buf.clone().freeze(); // Clone is cheap
    let ping = Ping::read_ping(&mut ping_buf, legacy)
        .await
        .context(PingDecode)?;
    debug!(?ping, ?addr, "ping read");

    let route_read = routes.read().await;
    let destination = {
        let hostname = ping.remove_fml();
        match route_read.get(hostname) {
            Some(dest) => dest.to_owned(),
            None => match route_read.get("*") {
                Some(dest) => dest.to_owned(),
                // There's nowhere to send them, so let's just ignore their entire ping.
                None => {
                    warn!(
                        "{} opened a connection but had no possible destination \
                        for the hostname {} (FML removed).",
                        addr, hostname,
                    );
                    return Ok(());
                }
            },
        }
    };
    let use_proxy_protocol = destination.proxy_protocol;
    info!(
        ?destination,
        ?addr,
        ?use_proxy_protocol,
        hostname = ping.hostname(),
        "proxying connection",
    );

    let mut outbound = TcpStream::connect(&destination.address)
        .await
        .context(DestinationConnectionUnattainable)?;
    outbound.set_nodelay(true).context(Io)?;
    debug!(
        ?addr,
        ?destination,
        ?outbound,
        ?use_proxy_protocol,
        "opened connection"
    );
    drop(route_read);
    if use_proxy_protocol {
        use proxy_protocol::version2::{ProxyAddresses, ProxyCommand, ProxyTransportProtocol};

        let local_addr = stream.local_addr().context(Io)?;

        let addresses = match (local_addr.ip(), addr.ip()) {
            (IpAddr::V4(local), IpAddr::V4(peer)) => ProxyAddresses::Ipv4 {
                source: (peer, Some(addr.port())),
                destination: (local, Some(local_addr.port())),
            },
            (local, peer) => ProxyAddresses::Ipv6 {
                source: (to_ipv6(peer), Some(addr.port())),
                destination: (to_ipv6(local), Some(local_addr.port())),
            },
        };
        let proxy = proxy_protocol::ProxyHeader::Version2 {
            command: ProxyCommand::Proxy,
            transport_protocol: ProxyTransportProtocol::Stream,
            addresses,
        };

        let encoded = proxy_protocol::encode(proxy).context(ProxyProtocolEncoding)?;
        outbound.write_all(&encoded).await.context(Io)?;
    }

    outbound.write_all(&buf).await.context(Io)?;
    outbound.flush().await.context(Io)?;
    debug!(?addr, "written client data");

    let (mut ri, mut wi) = stream.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    debug!(?addr, "joining copyers");
    let _ = futures::future::try_select(client_to_server.boxed(), server_to_client.boxed()).await;

    drop(ri);
    drop(wi);
    drop(ro);
    drop(wo);

    let _ = futures::future::join(stream.shutdown(), outbound.shutdown()).await;

    debug!(?addr, "finished with proxying");
    Ok(())
}

fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(v4) => v4.to_ipv6_compatible(),
    }
}
