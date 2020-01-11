#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

mod error;
mod ping;
mod varnum;

use self::prelude::*;
use bytes::{Buf as _, BytesMut};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use self::ping::Ping;

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
    let mut ping = Ping::read_ping(&mut stream, &mut buf, legacy).await?;
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
