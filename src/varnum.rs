use bytes::Buf;

pub fn read_varint_bytes(stream: &mut impl Buf) -> Option<(i32, usize)> {
    let mut x: i32 = 0;
    let mut bytes = 0;

    #[allow(clippy::erasing_op)]
    #[allow(clippy::identity_op)]
    #[allow(clippy::explicit_counter_loop)]
    for shift in [7 * 0u32, 7 * 1, 7 * 2, 7 * 3, 7 * 4].iter() {
        if !stream.has_remaining() {
            return None;
        }

        #[allow(clippy::cast_lossless)]
        let b = stream.get_u8() as i32;
        bytes += 1;
        x |= (b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            return Some((x, bytes));
        }
    }

    None
}
