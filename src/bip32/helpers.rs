
pub fn split_i(i: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut i_right = [0u8; 32];
    i_right.copy_from_slice(&i[32..]);

    let mut i_left = [0u8; 32];
    i_left.copy_from_slice(&i[0..32]);

    (i_left, i_right)
}

pub fn transform_u32_to_u8a(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}

