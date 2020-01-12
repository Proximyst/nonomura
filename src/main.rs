#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

mod error;
mod ping;
mod varnum;

use self::ping::Ping;
use self::prelude::*;
use bytes::{Buf as _, BytesMut};
use parking_lot::RwLock;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

pub mod prelude {
    pub use crate::error::*;
    pub use log::{debug, error, info, trace, warn};
}

type Routes = Arc<RwLock<HashMap<String, String>>>;

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
    let routes = Arc::new(RwLock::new(routes));
    // }}}

    let addr = env::var("ADDRESS")
        .ok()
        .unwrap_or_else(|| "0.0.0.0:25565".into());
    info!("Will attempt to listen on {}...", addr);

    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on {}.", addr);

    let accepting = tokio::spawn(accept_listeners(listener, Arc::clone(&routes)));
    let console = tokio::spawn(read_console(Arc::clone(&routes)));

    futures::future::try_join(accepting, console).await?;

    Ok(())
}

async fn accept_listeners(mut listener: TcpListener, routes: Routes) {
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

async fn read_console(routes: Routes) {
    use std::io::BufRead as _;

    let stdin = std::io::stdin();
    let lock = stdin.lock();

    for line in lock.lines() {
        let line: String = match line {
            Err(e) => {
                error!("Cannot read stdin: {:?}", e);
                return;
            }
            Ok(line) => line,
        };
        if line.eq_ignore_ascii_case("stop") {
            info!("Quitting application...");
            std::process::exit(0);
        }
        if line.eq_ignore_ascii_case("list") {
            let read = routes.read();
            info!("There are {} routes:", read.len());
            for (src, dest) in read.iter() {
                info!(" > {} <-> {}", src, dest);
            }
            continue;
        }
        if line.starts_with("rem") {
            let to_remove = line.split(' ').skip(1);
            let mut write = routes.write();
            for r in to_remove {
                match write.remove(r) {
                    None => info!(" > Route {} did not exist.", r),
                    Some(dest) => info!(" > Route {} to {} removed.", r, dest),
                }
            }
            continue;
        }
        if line.starts_with("add") {
            let mut to_add = line.split(' ').skip(1);
            let source = match to_add.next() {
                Some(s) => s,
                None => {
                    error!("syntax: add <source> <destination>");
                    continue;
                }
            };
            let dest = match to_add.next() {
                Some(d) => d,
                None => {
                    error!("syntax: add <source> <destination>");
                    continue;
                }
            };
            let mut write = routes.write();
            write.insert(source.to_owned(), dest.to_owned());
            info!(" > Added route from {} to {}.", source, dest);
            continue;
        }
        if line.eq_ignore_ascii_case("reload") {
            info!("Reading routes file...");
            let routes_file =
                env::var("ROUTES_FILE").unwrap_or_else(|_| String::from("routes.json"));
            let new: HashMap<String, String> = {
                let contents = match std::fs::read_to_string(&routes_file) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Cannot read routes file at {}: {:?}", routes_file, e);
                        continue;
                    }
                };
                match serde_json::from_str(&contents) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Cannot deserialize map of routes: {:?}", e);
                        continue;
                    }
                }
            };
            let mut write = routes.write();
            *write = new;
            continue;
        }
        if line.eq_ignore_ascii_case("write") {
            let read = routes.read();
            let routes_file =
                env::var("ROUTES_FILE").unwrap_or_else(|_| String::from("routes.json"));
            info!("Writing {} routes to {}...", read.len(), routes_file);
            let mapped = match serde_json::to_string_pretty(&*read) {
                Err(e) => {
                    error!("Cannot serialize routes: {:?}", e);
                    continue;
                },
                Ok(s) => s,
            };
            if let Err(e) = std::fs::write(&routes_file, mapped) {
                error!("Could not write to {}: {:?}", routes_file, e);
            }
            continue;
        }
    }
}

/// If a handshake begins with this monstrosity, it's a pre-rewrite ping and
/// must be handled accordingly.
const LEGACY_PING_PREFIX: [u8; 3] = [0xFE, 0x01, 0xFA];

async fn proxy(mut stream: TcpStream, addr: SocketAddr, routes: Routes) -> Result<()> {
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

    let destination = {
        let read = routes.read();
        match read.get(ping.hostname()) {
            Some(dest) => dest.to_owned(),
            // There's nowhere to send them, so let's just ignore their entire ping.
            None => return Ok(()),
        }
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
