//! The HAProxy PROXY protocol V2.
//!
//! The point of this is to *emit* PROXY headers, not to receive them, thus
//! I quite frankly don't care about parsing. Some of the parsing functions
//! required are implemented, but that's merely for the use of having excerpts
//! from the protocol around.
//!
//! This has been implemented by the specification:
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
#![allow(dead_code)] // Compiler bug - https://github.com/rust-lang/rust/issues/64362

use bytes::{BufMut as _, BytesMut};
use std::net::IpAddr;

use crate::prelude::*;

/// The 12 bytes required to notify of being a V2 binary PROXY protocol
/// connection.
///
/// Excerpt from the specification:
///
/// > The binary header format starts with a constant 12 bytes block containing the
/// > protocol signature :
/// >
/// >    `\x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A`
pub const BINARY_HEADER_PREFIX: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

#[derive(Debug)]
pub enum ProxyHeader {
    // Emitting this version does not support UNIX sockets.
    // The `rustc` optimiser should notice that the UNIX sockets in
    // `ProxyAddressFamily` is never constructed, and thus can be omitted, if
    // it isn't directly inlined.
    //
    // This version does not support extra data, as specified possible. Any
    // receiver shall therefore not believe so either.
    //
    // Excerpt from the specification:
    //
    // union proxy_addr {
    //     struct {        /* for TCP/UDP over IPv4, len = 12 */
    //         uint32_t src_addr;
    //         uint32_t dst_addr;
    //         uint16_t src_port;
    //         uint16_t dst_port;
    //     } ipv4_addr;
    //     struct {        /* for TCP/UDP over IPv6, len = 36 */
    //          uint8_t  src_addr[16];
    //          uint8_t  dst_addr[16];
    //          uint16_t src_port;
    //          uint16_t dst_port;
    //     } ipv6_addr;
    //     struct {        /* for AF_UNIX sockets, len = 216 */
    //          uint8_t src_addr[108];
    //          uint8_t dst_addr[108];
    //     } unix_addr;
    // };
    Version2 {
        command: ProxyCommand,
        transport_protocol: ProxyTransportProtocol,

        source_addr: IpAddr,

        /// If the destination address is not IPv6 while the client is, one can
        /// simply `address >> 8`, and let the highest 8 bytes be any value,
        /// preferably `0`.
        dest_addr: IpAddr,

        source_port: u16,
        dest_port: u16,
    },
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProxyCommand {
    Local = 0x0,
    Proxy = 0x1,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProxyVersion {
    Version2,
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProxyTransportProtocol {
    Unspec = 0x0,
    Stream = 0x1,
    DGram = 0x2,
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProxyAddressFamily {
    Unspec = 0x0,
    InetV4 = 0x1,
    InetV6 = 0x2,
    UnixSocket = 0x3,
}

impl ProxyHeader {
    pub fn encode(self) -> Result<BytesMut> {
        match self {
            Self::Version2 {
                command,
                transport_protocol,
                source_addr,
                dest_addr,
                source_port,
                dest_port,
            } => {
                let ipv4 = dest_addr.is_ipv4() && source_addr.is_ipv4();
                let address_family = if ipv4 { ProxyAddressFamily::InetV4 } else { ProxyAddressFamily::InetV6 };

                // The absolute minimum length of a header is 16 bytes.
                let mut bytes = BytesMut::with_capacity(16);
                bytes.put_slice(&BINARY_HEADER_PREFIX[..]);
                bytes.put_u8((0x2 << 4) | command as u8);
                bytes.put_u8(((address_family as u8) << 4) | transport_protocol as u8);
                let address_bytes_length = 
                    // The source_addr & dest_addr have to be the same length,
                    // so this is fine to just double.
                    ( if ipv4 { 4 * 2 } else { 8 * 2 } )
                    // A port has to be u16 either way, and there are two.
                    + ( 2 * 2 );
                bytes.put_u16(address_bytes_length);
                bytes.reserve(address_bytes_length as usize);

                if ipv4 {
                    let source_addr = match source_addr {
                        IpAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };
                    let dest_addr = match dest_addr {
                        IpAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };
                    bytes.put_slice(&source_addr.octets()[..]);
                    bytes.put_slice(&dest_addr.octets()[..]);
                } else {
                    let source_addr = match source_addr {
                        IpAddr::V6(addr) => addr,
                        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                    };
                    let dest_addr = match dest_addr {
                        IpAddr::V6(addr) => addr,
                        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                    };
                    bytes.put_slice(&source_addr.octets()[..]);
                    bytes.put_slice(&dest_addr.octets()[..]);
                }

                bytes.put_u16(source_port);
                bytes.put_u16(dest_port);

                Ok(bytes)
            }
        }
    }
}

impl ProxyVersion {
    pub fn read_version_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The highest four bits contains the version. As of this specification, it must
        // always be sent as \x2 and the receiver must only accept this value.

        Some(match byte >> 4 {
            0x2 => Self::Version2,
            _ => return None,
        })
    }
}

impl ProxyCommand {
    pub fn read_command_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The lowest four bits represents the command :
        //   - \x0 : LOCAL : the connection was established on purpose by the proxy
        //     without being relayed. The connection endpoints are the sender and the
        //     receiver. Such connections exist when the proxy sends health-checks to the
        //     server. The receiver must accept this connection as valid and must use the
        //     real connection endpoints and discard the protocol block including the
        //     family which is ignored.
        //
        //   - \x1 : PROXY : the connection was established on behalf of another node,
        //     and reflects the original connection endpoints. The receiver must then use
        //     the information provided in the protocol block to get original the address.
        //
        //   - other values are unassigned and must not be emitted by senders. Receivers
        //     must drop connections presenting unexpected values here.

        Some(match byte & 0b0000_1111 {
            0x0 => Self::Local,
            0x1 => Self::Proxy,
            _ => return None,
        })
    }
}

impl ProxyAddressFamily {
    pub fn read_family_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The 14th byte contains the transport protocol and address family. The highest 4
        // bits contain the address family, the lowest 4 bits contain the protocol.
        //
        // The address family maps to the original socket family without necessarily
        // matching the values internally used by the system. It may be one of :
        //
        //   - 0x0 : AF_UNSPEC : the connection is forwarded for an unknown, unspecified
        //     or unsupported protocol. The sender should use this family when sending
        //     LOCAL commands or when dealing with unsupported protocol families. The
        //     receiver is free to accept the connection anyway and use the real endpoint
        //     addresses or to reject it. The receiver should ignore address information.
        //
        //   - 0x1 : AF_INET : the forwarded connection uses the AF_INET address family
        //     (IPv4). The addresses are exactly 4 bytes each in network byte order,
        //     followed by transport protocol information (typically ports).
        //
        //   - 0x2 : AF_INET6 : the forwarded connection uses the AF_INET6 address family
        //     (IPv6). The addresses are exactly 16 bytes each in network byte order,
        //     followed by transport protocol information (typically ports).
        //
        //   - 0x3 : AF_UNIX : the forwarded connection uses the AF_UNIX address family
        //     (UNIX). The addresses are exactly 108 bytes each.
        //
        //   - other values are unspecified and must not be emitted in version 2 of this
        //     protocol and must be rejected as invalid by receivers.

        Some(match byte >> 4 {
            0x0 => Self::Unspec,
            0x1 => Self::InetV4,
            0x2 => Self::InetV6,
            0x3 => Self::UnixSocket,
            _ => return None,
        })
    }
}

impl ProxyTransportProtocol {
    pub fn read_protocol_binary(byte: u8) -> Option<Self> {
        // Excerpt from the specification:
        //
        // The 14th byte contains the transport protocol and address family. The highest 4
        // bits contain the address family, the lowest 4 bits contain the protocol.
        //
        // The transport protocol is specified in the lowest 4 bits of the 14th byte :
        //
        //   - 0x0 : UNSPEC : the connection is forwarded for an unknown, unspecified
        //     or unsupported protocol. The sender should use this family when sending
        //     LOCAL commands or when dealing with unsupported protocol families. The
        //     receiver is free to accept the connection anyway and use the real endpoint
        //     addresses or to reject it. The receiver should ignore address information.
        //
        //   - 0x1 : STREAM : the forwarded connection uses a SOCK_STREAM protocol (eg:
        //     TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the addresses
        //     are followed by the source and destination ports represented on 2 bytes
        //     each in network byte order.
        //
        //   - 0x2 : DGRAM : the forwarded connection uses a SOCK_DGRAM protocol (eg:
        //     UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6 (UDP), the addresses
        //     are followed by the source and destination ports represented on 2 bytes
        //     each in network byte order.
        //
        //   - other values are unspecified and must not be emitted in version 2 of this
        //     protocol and must be rejected as invalid by receivers.

        Some(match byte & 0b0000_1111 {
            0x0 => Self::Unspec,
            0x1 => Self::Stream,
            0x2 => Self::DGram,
            _ => return None,
        })
    }
}
