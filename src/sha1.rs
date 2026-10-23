/* cryptographic SHA-1 implementation adhering to FIPS PUB 180-4 and RFC 3174 */

pub const SHA1_DIGEST_LENGTH: usize = 20;
pub const SHA1_BLOCK_SIZE: usize = 64;

/* initial hash values defined by FIPS PUB 180-4 for SHA-1 */
const H0_INIT: u32 = 0x67452301;
const H1_INIT: u32 = 0xEFCDAB89;
const H2_INIT: u32 = 0x98BADCFE;
const H3_INIT: u32 = 0x10325476;
const H4_INIT: u32 = 0xC3D2E1F0;

/* round constants for each of the four 20-step execution phases */
const K_ROUND_0: u32 = 0x5A827999;
const K_ROUND_1: u32 = 0x6ED9EBA1;
const K_ROUND_2: u32 = 0x8F1BBCDC;
const K_ROUND_3: u32 = 0xCA62C1D6;

#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; SHA1_BLOCK_SIZE],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /* initialize SHA-1 state registers with standard constants */
    pub fn new() -> Self {
        Self {
            state: [H0_INIT, H1_INIT, H2_INIT, H3_INIT, H4_INIT],
            buffer: [0u8; SHA1_BLOCK_SIZE],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    /* ingest arbitrary byte slice into the streaming hasher */
    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let mut input = data;

        /* drain partial buffer if active bytes are waiting */
        if self.buffer_len > 0 {
            let needed = SHA1_BLOCK_SIZE - self.buffer_len;
            if input.len() >= needed {
                self.buffer[self.buffer_len..SHA1_BLOCK_SIZE].copy_from_slice(&input[..needed]);
                let block = self.buffer;
                Self::process_block(&mut self.state, &block);
                self.buffer_len = 0;
                input = &input[needed..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
        }

        /* process complete 64-byte blocks directly from the input slice */
        while input.len() >= SHA1_BLOCK_SIZE {
            let block: &[u8; SHA1_BLOCK_SIZE] = input[..SHA1_BLOCK_SIZE]
                .try_into()
                .expect("slice length verified to be 64 bytes");
            Self::process_block(&mut self.state, block);
            input = &input[SHA1_BLOCK_SIZE..];
        }

        /* store trailing remainder bytes in internal buffer */
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    /* finalize cryptographic state with padding and return 20-byte digest */
    pub fn finalize(mut self) -> [u8; SHA1_DIGEST_LENGTH] {
        let total_bits = self.total_bytes * 8;

        /* append single 0x80 delimiter bit byte per RFC 3174 */
        let mut pad = [0u8; SHA1_BLOCK_SIZE * 2];
        pad[0] = 0x80;

        let rem = (self.buffer_len + 1) % SHA1_BLOCK_SIZE;
        let pad_zeros = if rem <= 56 {
            56 - rem
        } else {
            SHA1_BLOCK_SIZE + 56 - rem
        };

        let pad_len = 1 + pad_zeros;
        self.update(&pad[..pad_len]);

        /* append big-endian 64-bit integer representing original message bit length */
        let bit_len_bytes = total_bits.to_be_bytes();
        self.update(&bit_len_bytes);

        /* export the five 32-bit registers as network byte order (big-endian) bytes */
        let mut digest = [0u8; SHA1_DIGEST_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        digest
    }

    /* convenient one-shot helper computing SHA-1 digest over a byte slice */
    pub fn digest(data: &[u8]) -> [u8; SHA1_DIGEST_LENGTH] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /* transform 512-bit (64-byte) message block using 80 expansion rounds */
    fn process_block(state: &mut [u32; 5], block: &[u8; SHA1_BLOCK_SIZE]) {
        /* message schedule array holding 80 expanded 32-bit words */
        let mut w = [0u32; 80];

        /* load sixteen 32-bit big-endian words from block */
        for (t, word) in w.iter_mut().enumerate().take(16) {
            let offset = t * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        /* expand schedule using bitwise XOR and 1-bit left circular rotation */
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        /* load working variables with current hash values */
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        /* execute 80 rounds partitioned into four 20-step functions */
        for (t, &w_t) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => {
                    /* non-linear conditional bit selection function */
                    ((b & c) | (!b & d), K_ROUND_0)
                }
                20..=39 => {
                    /* bitwise parity XOR function */
                    (b ^ c ^ d, K_ROUND_1)
                }
                40..=59 => {
                    /* bitwise majority function */
                    ((b & c) | (b & d) | (c & d), K_ROUND_2)
                }
                _ => {
                    /* bitwise parity XOR function */
                    (b ^ c ^ d, K_ROUND_3)
                }
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_t);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        /* add working variables back into state using wrapping 32-bit addition */
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* helper converting byte slice to lowercase hexadecimal string */
    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut s, "{:02x}", byte).unwrap();
        }
        s
    }

    #[test]
    fn test_sha1_empty_string() {
        /* verify against NIST standard test vector for empty string */
        let digest = Sha1::digest(b"");
        assert_eq!(
            to_hex(&digest),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_abc() {
        /* verify against NIST standard test vector for 'abc' */
        let digest = Sha1::digest(b"abc");
        assert_eq!(
            to_hex(&digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn test_sha1_fox() {
        /* verify against standard test vector for fox phrase */
        let digest = Sha1::digest(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            to_hex(&digest),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn test_sha1_long_message() {
        /* verify against NIST test vector for message exceeding single block */
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = Sha1::digest(msg);
        assert_eq!(
            to_hex(&digest),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }
}
