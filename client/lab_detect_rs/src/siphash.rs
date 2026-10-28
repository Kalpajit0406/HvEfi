// src/siphash.rs - SipHash-2-4 keyed PRF for hypercall authentication.
//
// Matches shared/hv_siphash.h bit-for-bit.

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13) ^ *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16) ^ *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21) ^ *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17) ^ *v2;
    *v2 = v2.rotate_left(32);
}

pub fn hv_siphash(k0: u64, k1: u64, msg: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let len = msg.len();
    let blocks = len / 8;

    for i in 0..blocks {
        let mut mi = 0u64;
        for b in 0..8 {
            mi |= (msg[i * 8 + b] as u64) << (8 * b);
        }
        v3 ^= mi;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= mi;
    }

    let mut last = ((len & 0xFF) as u64) << 56;
    let rem = len & 7;
    let tail = &msg[blocks * 8..];
    for i in 0..rem {
        last |= (tail[i] as u64) << (8 * i);
    }

    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xFF;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

pub fn hv_derive_session(ticket: &[u64; 4], nonce: u64) -> (u64, u64) {
    let nonce_bytes = nonce.to_le_bytes();
    let key0 = hv_siphash(ticket[0], ticket[1], &nonce_bytes);
    let inv = !nonce;
    let inv_bytes = inv.to_le_bytes();
    let key1 = hv_siphash(ticket[2], ticket[3], &inv_bytes);
    (key0, key1)
}

pub fn hv_session_magic(key0: u64, key1: u64) -> u64 {
    let tag: u64 = 0x4D4147494321; // 'MAGIC!'
    hv_siphash(key0, key1, &tag.to_le_bytes())
}

pub fn hv_boot_magic(ticket: &[u64; 4]) -> u64 {
    let tag: u64 = 0x2147414D54544F42; // 'BOTTMA\x47!' domain separator
    let mut words = [0u8; 40];
    words[0..8].copy_from_slice(&ticket[0].to_le_bytes());
    words[8..16].copy_from_slice(&ticket[1].to_le_bytes());
    words[16..24].copy_from_slice(&ticket[2].to_le_bytes());
    words[24..32].copy_from_slice(&ticket[3].to_le_bytes());
    words[32..40].copy_from_slice(&tag.to_le_bytes());

    hv_siphash(ticket[0] ^ ticket[2], ticket[1] ^ ticket[3], &words)
}

pub fn hv_mac_tuple(key0: u64, key1: u64, words: &[u64; 6]) -> u64 {
    let mut bytes = [0u8; 48];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    hv_siphash(key0, key1, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_magic_matches_c() {
        let ticket_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let mut ticket_words = [0u64; 4];
        for i in 0..4 {
            ticket_words[i] = u64::from_le_bytes(ticket_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        let magic = hv_boot_magic(&ticket_words);
        assert_eq!(magic, 0xF869878B883CC167);
    }
}
