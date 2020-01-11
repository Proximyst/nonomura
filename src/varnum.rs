use bytes::{Buf as _, BufMut as _, BytesMut};

use crate::prelude::*;

// {{{ read_varint_bytes(stream) -> Result<(int, read_bytes)>
pub fn read_varint_bytes(stream: &mut BytesMut) -> Result<(i32, usize)> {
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
pub fn varint_length(i: i32) -> usize {
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
pub fn write_varint(i: i32) -> BytesMut {
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
