pub fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut sha1 = SHA1::new();
    sha1.input(bytes);
    return sha1.result();
}

pub struct SHA1 {
    message_block_index: usize,
    message_block: [u8; 64],
    hash: [u32; 5],
    message_length: usize,
}

impl SHA1 {
    pub fn new() -> SHA1 {
        SHA1 {
            message_block_index: 0,
            message_block: [0; 64],
            hash: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            message_length: 0,
        }
    }

    pub fn input(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.message_block[self.message_block_index] = *byte;
            self.message_block_index += 1;
            self.message_length += 1;
            if self.message_block_index == self.message_block.len() {
                self.process_block();
            }
        }
    }

    pub fn result(mut self) -> [u8; 20] {
        let len = self.message_length as u64 * 8;
        self.input(&[0x80]);
        if self.message_block_index > 56 {
            while self.message_block_index > 1 {
                self.input(&[0x0]);
            }
        }
        while self.message_block_index < 56 {
            self.input(&[0x0]);
        }
        self.message_block[56] = (len >> 56) as u8;
        self.message_block[57] = (len >> 48) as u8;
        self.message_block[58] = (len >> 40) as u8;
        self.message_block[59] = (len >> 32) as u8;
        self.message_block[60] = (len >> 24) as u8;
        self.message_block[61] = (len >> 16) as u8;
        self.message_block[62] = (len >> 8) as u8;
        self.message_block[63] = len as u8;
        self.process_block();

        let mut result = [0; 20];
        for i in 0..20 {
            result[i] = (self.hash[i >> 2] >> (8 * (3 - (i & 0x03)))) as u8;
        }

        result
    }

    fn process_block(&mut self) {
        let k = [0x5A_82_79_99, 0x6E_D9_EB_A1, 0x8F_1B_BC_DC, 0xCA_62_C1_D6];
        let mut w = [0 as u32; 80];
        for i in 0..16 {
            w[i] = u32::from(self.message_block[i * 4]) << 24;
            w[i] |= u32::from(self.message_block[i * 4 + 1]) << 16;
            w[i] |= u32::from(self.message_block[i * 4 + 2]) << 8;
            w[i] |= u32::from(self.message_block[i * 4 + 3]);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];

        for i in 0..20 {
            let temp = a.rotate_left(5)
                .wrapping_add((b & c) | ((!b) & d))
                .wrapping_add(e)
                .wrapping_add(w[i])
                .wrapping_add(k[0]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for i in 20..40 {
            let temp = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(w[i])
                .wrapping_add(k[1]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for i in 40..60 {
            let temp = a.rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(w[i])
                .wrapping_add(k[2]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for i in 60..80 {
            let temp = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(w[i])
                .wrapping_add(k[3]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);

        self.message_block_index = 0;
    }
}

#[cfg(test)]
mod sha1_tests {
    use super::{sha1, SHA1};

    fn hex_string(bytes: &[u8]) -> String {
        let mut s = String::new();
        for byte in bytes {
            s += &format!("{:02X} ", byte);
        }
        let l = s.len();
        s.truncate(l - 1);
        return s;
    }

    #[test]
    fn everything_fits_in_one_message_block() {
        assert_eq!(
            hex_string(&sha1("abc".as_bytes())),
            "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D"
        );
    }

    #[test]
    fn not_enough_room_for_length_in_current_message_block() {
        assert_eq!(
            hex_string(&sha1(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            )),
            "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1"
        );
    }

    #[test]
    fn an_exact_multiple_of_512_bits() {
        let bytes = "0123456701234567012345670123456701234567012345670123456701234567".as_bytes();
        let mut sha1 = SHA1::new();
        for _ in 0..10 {
            sha1.input(bytes);
        }
        assert_eq!(
            hex_string(&sha1.result()),
            "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
        );
    }

    #[test]
    fn big_message() {
        let bytes = "a".as_bytes();
        let mut sha1 = SHA1::new();
        for _ in 0..1000000 {
            sha1.input(bytes);
        }
        assert_eq!(
            hex_string(&sha1.result()),
            "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F"
        );
    }
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let ipad = [0x36; 64];
    let opad = [0x5c; 64];
    let key = fix_key(key);
    let hash1 = sha1(&[&xor(key, ipad), data].concat());
    let hash2 = sha1(&[&xor(key, opad) as &[u8], &hash1].concat());
    return hash2;
}

fn xor(a: [u8; 64], b: [u8; 64]) -> [u8; 64] {
    let mut result = [0; 64];
    for i in 0..64 {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

fn fix_key(key: &[u8]) -> [u8; 64] {
    let hashed_key;
    let key = if key.len() > 64 {
        hashed_key = sha1(&key);
        &hashed_key
    } else {
        key
    };
    let mut result = [0; 64];
    result[..key.len()].clone_from_slice(&key);
    return result;
}

#[cfg(test)]
mod hmac_tests {
    use super::hmac_sha1;

    #[test]
    fn rfc_2202_test_case_1() {
        let key = [0x0b; 20];
        let data = "Hi There".as_bytes();
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
            ]
        )
    }

    #[test]
    fn rfc_2202_test_case_2() {
        let key = "Jefe".as_bytes();
        let data = "what do ya want for nothing?".as_bytes();
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
            ]
        )
    }

    #[test]
    fn rfc_2202_test_case_3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1,
                0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3
            ]
        )
    }

    #[test]
    fn rfc_2202_test_case_4() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let data = [0xcd; 50];
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50,
                0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda
            ]
        )
    }

    #[test]
    fn rfc_2202_test_case_5() {
        let key = [0x0c; 20];
        let data = "Test With Truncation".as_bytes();
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b,
                0xb9, 0x32, 0x4a, 0x9a, 0x5a, 0x04
            ]
        )
    }

    #[test]
    fn rfc_2202_test_case_6() {
        let key = [0xaa; 80];
        let data = "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes();
        assert_eq!(
            hmac_sha1(&key, &data),
            [
                0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a,
                0x3b, 0x55, 0xed, 0x40, 0x21, 0x12
            ]
        )
    }
}
