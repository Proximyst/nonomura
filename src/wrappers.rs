use log::{debug, error};
use std::{
    convert::{AsMut, AsRef},
    net::{Shutdown, SocketAddr},
    ops::{Deref, DerefMut},
};
use tokio::{io::ErrorKind, net::TcpStream};

pub struct TcpStreamWrapper(pub TcpStream, pub SocketAddr);

impl AsRef<TcpStream> for TcpStreamWrapper {
    fn as_ref(&self) -> &TcpStream {
        &self.0
    }
}

impl AsMut<TcpStream> for TcpStreamWrapper {
    fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.0
    }
}

impl Deref for TcpStreamWrapper {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TcpStreamWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for TcpStreamWrapper {
    fn drop(&mut self) {
        if let Err(e) = self.0.shutdown(Shutdown::Both) {
            let e: failure::Error = e.into();
            if let Some(e) = e.downcast_ref::<tokio::io::Error>() {
                match e.kind() {
                    // All disconnection errors by A) actual disconnect
                    // or B) by invalid data off the bat are to be thrown
                    // away.
                    ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::NotConnected
                    | ErrorKind::TimedOut
                    | ErrorKind::InvalidData => {
                        debug!("Disconnected {}; error: {:?}", self.1, e);
                    }

                    e => {
                        error!("Error during proxying {}: {:?}", self.1, e);
                    }
                }
            } else {
                error!("Error during proxying {}: {:?}", self.1, e);
            }
        }
    }
}
