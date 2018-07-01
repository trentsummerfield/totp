mod base32;
mod hash;

pub fn totp(secret: &str, epoch_secs: u64) -> Option<String> {
    let secret_bytes = base32::decode(secret)?;
    let time = epoch_secs / 30;
    let hash = hash::hmac_sha1(&secret_bytes, &u64_to_bytes(time));
    let index = (hash[19] & 0xF) as usize;
    let long_code = ((hash[index] & 0x7F) as u32) << 24
        | (hash[index + 1] as u32) << 16
        | (hash[index + 2] as u32) << 8
        | (hash[index + 3] as u32);
    let code = long_code % 1_000_000;
    return Some(format!("{:<06}", code));
}

fn u64_to_bytes(x: u64) -> [u8; 8] {
    return [
        (x >> 56) as u8,
        (x >> 48) as u8,
        (x >> 40) as u8,
        (x >> 32) as u8,
        (x >> 24) as u8,
        (x >> 16) as u8,
        (x >> 8) as u8,
        x as u8,
    ];
}

#[cfg(test)]
mod tests {
    use totp;

    #[test]
    fn totp_test() {
        let secret = "XEXW5BSAXP4IFA2V";
        let time = 1530334470 as u64;
        assert_eq!(totp(secret, time).unwrap(), "013549");
    }
}
