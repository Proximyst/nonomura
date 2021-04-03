use crate::prelude::*;
use crate::varnum::read_varint_bytes;
use bytes::Buf;
use snafu::{ensure, OptionExt as _};

#[derive(Debug, Snafu)]
pub enum Error {
    UnexpectedEof,
    IoRead { source: std::io::Error },

    UnreadableHostname { source: std::str::Utf8Error },

    InvalidLegacyPingPrefix,
    InvalidLegacyPingMagic,
    InvalidLegacyPingHostname,

    InvalidHostnameLength { len: i32 },
    InvalidVarInt,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, PartialEq, Eq)]
pub enum Ping {
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
    pub async fn read_ping(buf: &mut impl Buf, is_legacy: bool) -> Result<Self> {
        if is_legacy {
            Self::read_legacy_ping(buf).await
        } else {
            Self::read_netty_ping(buf).await
        }
    }

    pub fn hostname(&self) -> &str {
        match self {
            Self::Netty { ref address, .. } => address,
            Self::Legacy { ref hostname, .. } => hostname,
        }
    }

    pub fn remove_fml(&self) -> &str {
        let hostname = self.hostname();
        if hostname.ends_with("FML2") {
            hostname.trim_end_matches("FML2")
        } else if hostname.ends_with("FML") {
            hostname.trim_end_matches("FML")
        } else {
            hostname
        }
    }

    /// Reads a ping from the legacy standard.
    ///
    /// Format and details: <https://wiki.vg/Server_List_Ping#1.6>
    async fn read_legacy_ping(buf: &mut impl Buf) -> Result<Self> {
        // Look for 48 00 6F 00 73 00 74 ?? ?? ??.
        // The hostname length is then the 2 next bytes, then comes the
        // hostname itself as a UTF-16BE string.

        // 3 for prefix;
        // 2 for length of magic string;
        // 22 for entire magic string;
        // 2 for length of rest
        //
        // Ensure the prefix is correct.
        ensure!(buf.remaining() >= 3, UnexpectedEof);
        ensure!(
            buf.get_u8() == 0xFE && buf.get_u8() == 0x01 && buf.get_u8() == 0xFA,
            InvalidLegacyPingPrefix,
        );

        // Length of the following string.
        // Any Notchian client sends 11 here, so we'll require that. Cheaters
        // and other malicious clients that pointlessly change this get
        // disconnected, and that's something I'm fine with.
        ensure!(buf.remaining() >= 2, UnexpectedEof);
        ensure!(buf.get_u16() == 11, InvalidLegacyPingMagic);

        // We should now have 11 chars (22 bytes) we can just throw away.
        ensure!(buf.remaining() >= 22, UnexpectedEof);
        for _ in 0..22 {
            let _ = buf.get_u8();
        }

        ensure!(buf.remaining() >= 5, UnexpectedEof);
        let length = buf.get_i16() as usize;
        ensure!(buf.remaining() >= length, UnexpectedEof);
        let version = buf.get_u8();

        let hostname_length = buf.get_i16();
        ensure!(
            hostname_length < 255 && hostname_length > 0,
            InvalidHostnameLength {
                len: hostname_length as i32,
            },
        );

        ensure!(
            buf.remaining() >= hostname_length as usize * 2,
            UnexpectedEof
        );
        let hostname = {
            let raw = buf.copy_to_bytes(hostname_length as usize * 2);
            encoding_rs::UTF_16BE.decode(&raw).0.to_string()
        };

        ensure!(buf.remaining() >= 4, UnexpectedEof);
        let port = buf.get_i32();

        Ok(Self::Legacy {
            version,
            hostname,
            port,
        })
    }

    /// Reads a ping from the current standard.
    ///
    /// Formats and details: <https://wiki.vg/Server_List_Ping#Current>
    async fn read_netty_ping(buf: &mut impl Buf) -> Result<Self> {
        // Format: vi_Length, vi_PacketID, b_Data[]
        // Data should be: vi_ProtocolVer, vi_HostNameLen, s_HostName, ...
        // This means we need to find vi_HostNameLen & s_HostName.

        // Ensure we have enough to read the entire potential length
        ensure!(buf.remaining() >= 3, UnexpectedEof);
        let (length, _) = read_varint_bytes(buf).context(InvalidVarInt)?;

        ensure!(buf.remaining() >= length as usize, UnexpectedEof);
        let (_packet_id, _) = read_varint_bytes(buf).context(InvalidVarInt)?;
        let (protocol_ver, _) = read_varint_bytes(buf).context(InvalidVarInt)?;

        let (hostname_length, _) = read_varint_bytes(buf).context(InvalidVarInt)?;
        ensure!(
            hostname_length < 255 && hostname_length > 0,
            InvalidHostnameLength {
                len: hostname_length,
            },
        );

        let hostname = buf.copy_to_bytes(hostname_length as usize);
        let hostname = std::str::from_utf8(&hostname)
            .context(UnreadableHostname)?
            .to_owned();

        let port = buf.get_u16();

        let (next_state, _) = read_varint_bytes(buf).context(InvalidVarInt)?;

        Ok(Self::Netty {
            version: protocol_ver,
            address: hostname,
            port,
            next_state,
        })
    }
}
