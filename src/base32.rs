pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 8 != 0 {
        return None;
    }
    let mut result = Vec::new();
    for i in 0..(s.len() / 8) {
        let offset = i * 8;
        let bytes = base32_decode_block(&s[offset..(offset + 8)])?;
        for b in &bytes {
            result.push(b.clone());
        }
    }
    return Some(result);
}

fn base32_decode_block(s: &str) -> Option<[u8; 5]> {
    let mut result = [0 as u8; 5];
    result[0] = char_to_byte(char_at(s, 0))? << 3 | char_to_byte(char_at(s, 1))? >> 2;
    result[1] = char_to_byte(char_at(s, 1))? << 6
        | char_to_byte(char_at(s, 2))? << 1
        | char_to_byte(char_at(s, 3))? >> 4;
    result[2] = char_to_byte(char_at(s, 3))? << 4 | char_to_byte(char_at(s, 4))? >> 1;
    result[3] = char_to_byte(char_at(s, 4))? << 7
        | char_to_byte(char_at(s, 5))? << 2
        | char_to_byte(char_at(s, 6))? >> 3;
    result[4] = char_to_byte(char_at(s, 6))? << 5 | char_to_byte(char_at(s, 7))?;
    return Some(result);
}

fn char_at(s: &str, n: usize) -> char {
    return s.chars().nth(n).unwrap();
}

const CHAR_TO_BYTE: [char; 32] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7',
];

fn char_to_byte(c: char) -> Option<u8> {
    for (i, k) in CHAR_TO_BYTE.iter().enumerate() {
        if c == *k {
            return Some(i as u8);
        }
    }
    return None;
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn base32() {
        assert_eq!(decode("MZXW6YTB").unwrap(), "fooba".as_bytes());
    }

    #[test]
    fn base32_long() {
        assert_eq!(
            decode("XEXW5BSAXP4IFA2V").unwrap(),
            [0xB9, 0x2F, 0x6E, 0x86, 0x40, 0xBB, 0xF8, 0x82, 0x83, 0x55]
        );
    }
}
