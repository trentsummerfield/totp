mod hash;

 /// Computes a 6-digit code based on the given secret and time according to RFC 6238. 
 ///
 /// A timestep of 30 seonds is assumed.
 /// 
 /// # Examples
 /// ```rust
 /// let secret = [0xB9, 0x2F, 0x6E, 0x86, 0x40, 0xBB, 0xF8, 0x82, 0x83, 0x55];
 /// let time = 1530334470 as u64;
 /// assert_eq!(totp::totp(&secret, time), "013549");
 /// ```
pub fn totp(secret: &[u8], epoch_secs: u64) -> String {
    let time = epoch_secs / 30;
    let hash = hash::hmac_sha1(secret, &u64_to_bytes(time));
    let index = (hash[19] & 0xF) as usize;
    let long_code = ((hash[index] & 0x7F) as u32) << 24
        | (hash[index + 1] as u32) << 16
        | (hash[index + 2] as u32) << 8
        | (hash[index + 3] as u32);
    let code = long_code % 1_000_000;
    return format!("{:<06}", code);
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
