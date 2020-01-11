#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

mod error;

use self::prelude::*;
use bytes::{Buf as _, BufMut as _, BytesMut};
use encoding::Encoding as _;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

pub mod prelude {
    pub use crate::error::*;
    pub use log::{debug, error, info, trace, warn};
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // {{{ setting up simplelog
    {
        use simplelog::*;
        CombinedLogger::init(vec![TermLogger::new(
            if cfg!(debug_assertions) {
                LevelFilter::Trace
            } else {
                LevelFilter::Info
            },
            Config::default(),
            TerminalMode::Mixed,
        )
        .unwrap()])
        .unwrap();
    }
    // }}}

    // {{{ reading routes
    info!("Reading routes file...");
    let routes_file = env::var("ROUTES_FILE").unwrap_or_else(|_| String::from("routes.json"));
    let routes: HashMap<String, String> = {
        let contents = std::fs::read_to_string(routes_file)?;
        serde_json::from_str(&contents)?
    };
    if routes.is_empty() {
        return Err(InitError::NoRoutes.failure().into());
    }
    info!("{} routes loaded.", routes.len());
    if log::log_enabled!(log::Level::Debug) {
        debug!("Displaying all loaded routes:");
        for (route, dest) in &routes {
            debug!("{} routed to {}", route, dest);
        }
    }
    let routes = Arc::new(routes);
    // }}}

    let addr = env::var("ADDRESS")
        .ok()
        .unwrap_or_else(|| "0.0.0.0:25565".into());
    info!("Will attempt to listen on {}...", addr);

    let mut listener = TcpListener::bind(&addr).await?;
    info!("Listening on {}.", addr);

    loop {
        let (stream, addr): (TcpStream, SocketAddr) = match listener.accept().await {
            Ok(ok) => ok,
            Err(e) => {
                error!("Error occurred while listening: {:?}", e);
                continue;
            }
        };

        info!("Connection opened from {}.", addr);

        let routes = Arc::clone(&routes);
        let proxy = async move {
            if let Err(e) = proxy(stream, addr, routes).await {
                error!("Error during proxying {}: {:?}", addr, e);
            }
        };
        tokio::spawn(proxy);
    }
}

/// If a handshake begins with this monstrosity, it's a pre-rewrite ping and
/// must be handled accordingly.
const LEGACY_PING_PREFIX: [u8; 3] = [0xFE, 0x01, 0xFA];

async fn proxy(
    mut stream: TcpStream,
    addr: SocketAddr,
    routes: Arc<HashMap<String, String>>,
) -> Result<()> {
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

    // {{{ read initial buffer and determine legacy
    let mut buf = BytesMut::with_capacity(3);
    stream.read_buf(&mut buf).await?;
    while buf.len() < 3 {
        stream.read_buf(&mut buf).await?;
        tokio::time::delay_for(Duration::from_millis(1)).await;

        // Ensure we have the 3 bytes we require first.
    }
    let legacy = buf == LEGACY_PING_PREFIX[..];
    // }}}

    // We know if it's legacy now, and thus know how to read the hostname.
    let mut ping = // {{{ read ping
        if legacy {
        trace!("{} is a legacy ping.", addr);

        read_legacy_ping(&mut stream, &mut buf).await?
    } else {
        trace!("{} is a standard ping.", addr);

        read_netty_ping(&mut stream, &mut buf).await?
    };
    // }}}
    trace!("{} ping resolved as: {:?}", addr, ping);

    let destination = match routes.get(ping.hostname()) {
        Some(dest) => dest,
        // There's nowhere to send them, so let's just ignore their entire ping.
        None => return Ok(()),
    };
    let mut outbound = match TcpStream::connect(destination).await.ok() {
        Some(o) => o,
        // Server isn't up, let's just close the connection.
        None => return Ok(()),
    };

    // {{{ re-do ping
    ping.set_ip(addr.to_string());

    let encoded = ping.encode();
    let encoded = encoded.bytes();
    outbound.write_all(encoded).await?;
    outbound.flush().await?;
    // }}}

    // {{{ copy data back and forth
    let (mut ri, mut wi) = stream.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    trace!("Joining copyers...");
    futures::future::try_join(client_to_server, server_to_client).await?;
    // }}}

    Ok(())
}

/// Reads a ping from the legacy standard.
///
/// Format and details: <https://wiki.vg/Server_List_Ping#1.6>
// {{{ read_legacy_ping(stream, buf) -> Result<Ping::Legacy>
async fn read_legacy_ping(stream: &mut TcpStream, buf: &mut BytesMut) -> Result<Ping> {
    // Look for 48 00 6F 00 73 00 74 ?? ?? ??.
    // The hostname length is then the 2 next bytes, then comes the
    // hostname itself as a UTF-16BE string.

    // 2 bytes for length of MC|PingHost, 11 for MC|PingHost, 2 for length
    // of the rest of the packet.
    buf.reserve(15);
    while buf.remaining() < buf.capacity() {
        stream.read_buf(buf).await?;
        tokio::time::delay_for(Duration::from_millis(2)).await;
    }
    stream.read_buf(buf).await?;

    // Ensure the prefix is correct.
    if buf.get_u8() != 0xFE || buf.get_u8() != 0x01 || buf.get_u8() != 0xFA {
        return Err(ReadError::InvalidLegacyPing.into());
    }

    // Length of the following string.
    // Any Notchian client sends 11 here, so we'll require that. Cheaters
    // and other malicious clients can have an error.
    if buf.get_u16() != 11 {
        return Err(ReadError::InvalidLegacyPing.into());
    }

    // We should now have 11 chars (22 bytes) we can just throw away.
    for _ in 0..22 {
        let _ = buf.get_u8();
    }

    let length = buf.get_i16() as usize;
    buf.reserve(length);
    while buf.remaining() < length {
        stream.read_buf(buf).await?;
        tokio::time::delay_for(Duration::from_millis(2)).await;
    }
    // The rest of the packet should now be available.

    let version = buf.get_u8();

    let hostname_length = buf.get_i16();
    if hostname_length > 255 {
        return Err(ReadError::LongStringLength.into());
    } else if hostname_length <= 0 {
        return Err(ReadError::ShortStringLength.into());
    }

    let hostname = {
        let mut bytes = BytesMut::with_capacity(hostname_length as usize);
        for _ in 0..hostname_length * 2 {
            bytes.put_u8(buf.get_u8());
        }
        match encoding::codec::utf_16::UTF_16BE_ENCODING
            .decode(bytes.bytes(), encoding::DecoderTrap::Strict)
        {
            Ok(s) => s,
            Err(e) => return Err(ReadError::EncodingError(e.into_owned()).into()),
        }
    };

    let port = buf.get_i32();

    Ok(Ping::Legacy {
        version,
        hostname,
        port,
    })
}
// }}}

/// Reads a ping from the current standard.
///
/// Formats and details: <https://wiki.vg/Server_List_Ping#Current>
// {{{ read_netty_ping(stream, buf) -> Result<Ping::Netty>
async fn read_netty_ping(stream: &mut TcpStream, buf: &mut BytesMut) -> Result<Ping> {
    // Format: vi_Length, vi_PacketID, b_Data[]
    // Data should be: vi_ProtocolVer, vi_HostNameLen, s_HostName, ...
    // This means we need to find vi_HostNameLen & s_HostName.

    buf.reserve(2);
    stream.read_buf(buf).await?;

    let (length, _) = read_varint_bytes(buf)?;

    buf.reserve(length as usize - buf.remaining());
    while buf.len() != buf.capacity() {
        stream.read_buf(buf).await?;
        tokio::time::delay_for(Duration::from_millis(2)).await;
    }

    let (_packet_id, _) = read_varint_bytes(buf)?;

    let (protocol_ver, _) = read_varint_bytes(buf)?;

    let (hostname_length, _) = read_varint_bytes(buf)?;
    if hostname_length > 255 {
        return Err(ReadError::LongStringLength.into());
    } else if hostname_length <= 0 {
        return Err(ReadError::ShortStringLength.into());
    }

    let mut hostname = BytesMut::with_capacity(hostname_length as usize);
    for _ in 0..hostname_length {
        hostname.put_u8(buf.get_u8());
    }
    let hostname = std::str::from_utf8(hostname.bytes())?.to_owned();

    let port = buf.get_u16();

    let (next_state, _) = read_varint_bytes(buf)?;

    Ok(Ping::Netty {
        version: protocol_ver,
        address: hostname,
        port,
        next_state,
    })
}
// }}}

// {{{ read_varint_bytes(stream) -> Result<(int, read_bytes)>
fn read_varint_bytes(stream: &mut BytesMut) -> Result<(i32, usize)> {
    let mut x: i32 = 0;
    let mut bytes = 0;

    #[allow(clippy::erasing_op)]
    #[allow(clippy::identity_op)]
    #[allow(clippy::explicit_counter_loop)]
    for shift in [7 * 0u32, 7 * 1, 7 * 2, 7 * 3, 7 * 4].iter() {
        #[allow(clippy::cast_lossless)]
        let b = stream.get_u8() as i32;
        bytes += 1;
        x |= (b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            return Ok((x, bytes));
        }
    }

    Err(ReadError::VarInt.into())
}
// }}}

// {{{ varint_length(i) -> usize
fn varint_length(i: i32) -> usize {
    let value = i as u32;
    for i in 1..5 {
        if (value & 0xffff_ffffu32 << (7 * i)) == 0 {
            return i;
        }
    }
    5
}
// }}}

// {{{ write_varint(i) -> BytesMut
fn write_varint(i: i32) -> BytesMut {
    let mut buf = BytesMut::with_capacity(varint_length(i));

    let mut temp = i as u32;
    loop {
        if (temp & !0x7fu32) == 0 {
            buf.put_u8(temp as u8);
            return buf;
        } else {
            buf.put_u8(((temp & 0x7F) | 0x80) as u8);
            temp >>= 7;
        }
    }
}
// }}}

#[derive(Debug, PartialEq, Eq)]
enum Ping {
    Netty {
        version: i32,
        address: String,
        port: u16,
        next_state: i32,
    },
    Legacy {
        version: u8,
        hostname: String,
        port: i32,
    },
}

impl Ping {
    // {{{ hostname, set_ip(ip), encode
    pub fn hostname(&self) -> &str {
        match self {
            Ping::Netty { ref address, .. } => address,
            Ping::Legacy { ref hostname, .. } => hostname,
        }
    }

    pub fn set_ip(&mut self, ip: String) {
        match self {
            Ping::Netty { address, .. } => {
                let mut new: String = format!("{}${}", address, ip);
                if new.len() > 255 {
                    new = new.chars().skip(new.len() - 255).collect();
                }
                *address = new;
            }
            Ping::Legacy { hostname, .. } => {
                let mut new: String = format!("{}${}", hostname, ip);
                if new.len() > 255 {
                    new = new.chars().skip(new.len() - 255).collect();
                }
                *hostname = new;
            }
        }
    }

    pub fn encode(self) -> BytesMut {
        match self {
            Ping::Netty {
                version,
                address,
                port,
                next_state,
            } => Self::write_netty_ping(version, address, port, next_state),
            Ping::Legacy {
                version,
                hostname,
                port,
            } => Self::write_legacy_ping(version, hostname, port),
        }
    }
    // }}}

    // {{{ internal encoding methods
    fn write_netty_ping(version: i32, address: String, port: u16, next_state: i32) -> BytesMut {
        let address_bytes = address.as_bytes();
        let data_size = varint_length(0x00)
            + varint_length(version)
            + varint_length(address_bytes.len() as i32)
            + address_bytes.len()
            + 2
            + varint_length(next_state);
        let mut bytes = BytesMut::with_capacity(varint_length(data_size as i32) + data_size);
        bytes.put(write_varint(data_size as i32));
        bytes.put(write_varint(0x00));
        bytes.put(write_varint(version));
        bytes.put(write_varint(address_bytes.len() as i32));
        bytes.put_slice(address_bytes);
        bytes.put_u16(port);
        bytes.put(write_varint(next_state));
        bytes
    }

    fn write_legacy_ping(version: u8, hostname: String, port: i32) -> BytesMut {
        let mut bytes =
            BytesMut::with_capacity(1 + 1 + 1 + 2 + 22 + 4 + 1 + 2 + hostname.len() * 2 + 4);
        for b in [
            0xFE, 0x01, 0xFA, 0x00, 0x0B, 0x00, 0x4D, 0x00, 0x43, 0x00, 0x7C, 0x00, 0x50, 0x00,
            0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x48, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74,
        ]
        .iter()
        {
            bytes.put_u8(*b);
        }

        bytes.put_u16(7 + hostname.len() as u16 * 2);
        bytes.put_u8(version);
        bytes.put_u16(hostname.len() as u16 * 2);
        for b in encoding::codec::utf_16::UTF_16BE_ENCODING
            .encode(&hostname, encoding::EncoderTrap::Ignore)
            .expect("could not encode hostname")
        {
            bytes.put_u8(b);
        }
        bytes.put_i32(port);

        bytes
    }
    // }}}
}
