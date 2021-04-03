#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

mod ping;
mod proxy;
mod varnum;

use self::prelude::*;
use eyre::{eyre, Report, WrapErr as _};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tokio::{
    io::ErrorKind,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

pub mod prelude {
    pub use bytes::{Buf, BufMut, Bytes, BytesMut};
    pub use snafu::{ResultExt, Snafu};
    pub use tracing::{debug, error, info, trace, warn};

    pub fn reserve_at_least(buf: &mut BytesMut, bytes: usize) {
        let cap = buf.capacity();
        if cap < bytes {
            // This will likely reserve a fair bit more.
            buf.reserve(bytes - cap);
        }
    }
}

type Routes = Arc<RwLock<HashMap<String, Route>>>;

#[tokio::main]
async fn main() -> Result<(), Report> {
    // We first need Eyre to work correctly...
    stable_eyre::install()?;

    // Now to init the .env file...
    match dotenv::dotenv() {
        Ok(_) => (),
        Err(e) if e.not_found() => (),
        Err(e) => {
            return Err(e).wrap_err(".env file could not be loaded");
        }
    }

    // And now tracing, as that depends on .env...
    tracing_subscriber::fmt::init();

    info!(concat!(
        env!("CARGO_PKG_NAME"),
        " (v",
        env!("CARGO_PKG_VERSION"),
        ")"
    ));
    info!(
        "
    nonomura: a virtual host reverse proxy for Minecraft
    Copyright (C) 2021 {}

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
",
        env!("CARGO_PKG_AUTHORS")
    );

    let routes_file = env::var("ROUTES_FILE").unwrap_or_else(|_| String::from("routes.json"));
    let routes: HashMap<String, Route> = {
        let contents = std::fs::read_to_string(routes_file)?;
        serde_json::from_str(&contents)?
    };
    if routes.is_empty() {
        return Err(eyre!("no routes were found"));
    }
    debug!(?routes, "routes were loaded");
    let routes = Arc::new(RwLock::new(routes));

    let addr = env::var("ADDRESS")
        .ok()
        .unwrap_or_else(|| "0.0.0.0:25565".into());
    debug!(?addr, "binding to address");

    let listener = TcpListener::bind(&addr).await?;

    accept_listeners(listener, Arc::clone(&routes)).await;

    Ok(())
}

async fn accept_listeners(listener: TcpListener, routes: Routes) {
    loop {
        let (stream, addr): (TcpStream, SocketAddr) = match listener.accept().await {
            Ok(ok) => ok,
            Err(e) => {
                error!("Error occurred while listening: {:?}", e);
                continue;
            }
        };

        let routes = Arc::clone(&routes);
        let proxy = async move {
            let mut stream = stream; // Force a move
            let addr = addr; // Force a move

            if let Err(e) = proxy::proxy(&mut stream, routes).await {
                if let proxy::ProxyError::Io { source } = e {
                    match source.kind() {
                        // All disconnection errors by A) actual disconnect
                        // or B) by invalid data off the bat are to be thrown
                        // away.
                        ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::NotConnected
                        | ErrorKind::TimedOut
                        | ErrorKind::InvalidData => {
                            debug!(?source, ?addr, "connection closed");
                        }

                        _ => {
                            error!(?source, ?addr, "error during proxy");
                        }
                    }
                } else {
                    error!(?e, ?addr, "error during proxy");
                }
            }
        };

        tokio::spawn(proxy);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub address: SocketAddr,
    pub proxy_protocol: bool,
}
