use crate::varnum::*;
use bytes::{Buf as _, BufMut as _, BytesMut};
use encoding::Encoding as _;
use std::time::Duration;
use tokio::{io::AsyncReadExt as _, net::TcpStream};

use crate::prelude::*;

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362
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
    pub async fn read_ping(stream: &mut TcpStream, buf: &mut BytesMut, is_legacy: bool) -> Result<Self> {
        if is_legacy {
            Self::read_legacy_ping(stream, buf).await
        } else {
            Self::read_netty_ping(stream, buf).await
        }
    }

    // {{{ hostname, set_ip(ip), encode
    pub fn hostname(&self) -> &str {
        match self {
            Self::Netty { ref address, .. } => address,
            Self::Legacy { ref hostname, .. } => hostname,
        }
    }

    pub fn set_ip(&mut self, ip: String) {
        match self {
            Self::Netty { address, .. } => {
                let mut new: String = format!("{}${}", address, ip);
                if new.len() > 255 {
                    new = new.chars().skip(new.len() - 255).collect();
                }
                *address = new;
            }
            Self::Legacy { hostname, .. } => {
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
            Self::Netty {
                version,
                address,
                port,
                next_state,
            } => Self::write_netty_ping(version, address, port, next_state),
            Self::Legacy {
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

    /// Reads a ping from the legacy standard.
    ///
    /// Format and details: <https://wiki.vg/Server_List_Ping#1.6>
    // {{{ read_legacy_ping(stream, buf) -> Result<Ping::Legacy>
    async fn read_legacy_ping(stream: &mut TcpStream, buf: &mut BytesMut) -> Result<Self> {
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

        Ok(Self::Legacy {
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
    async fn read_netty_ping(stream: &mut TcpStream, buf: &mut BytesMut) -> Result<Self> {
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

        Ok(Self::Netty {
            version: protocol_ver,
            address: hostname,
            port,
            next_state,
        })
    }
    // }}}
}
