use std::mem::transmute;

static H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[allow(dead_code)]
pub struct SHA256 {
    state: [u32; 8],
    completed_data_blocks: u64,
    pending: [u8; 64],
    num_pending: usize,
}

impl SHA256 {
    pub fn new() -> Self {
        Self {
            state: H,
            completed_data_blocks: 0,
            pending: [0u8; 64],
            num_pending: 0,
        }
    }

    pub fn push(&mut self, data: &[u8; 64]) {
        let mut h = self.state;

        let mut w = [0u32; 64];
        let data = unsafe { transmute::<_, [u32; 16]>(*data) };
        for i in 0..16 { w[i] = data[i]; }

        let [mut s0, mut s1, mut t1, mut t2, mut ch, mut ma]: [u32; 6];

        for i in 16..64 {
            s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        for i in 0..64 {
            ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
            ma = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            t1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            t2 = s0.wrapping_add(ma);

            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t1.wrapping_add(t2);
        }

        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(h[i]);
        }
    }

    pub fn state(&self) -> [u32; 8] { self.state }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest;

    fn flip32(data: &mut [u8]) -> &[u8] {
        let len = data.len();
        assert_eq!(len % 4, 0);
        for i in 0..len / 4 { data[i * 4..(i * 4 + 4)].reverse(); }
        data
    }

    #[test]
    fn state() {
        let mut data = *b"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";

        let mut sha256 = SHA256::new();
        sha256.push(&data);

        #[allow(dead_code)]
        struct Context {
            state: [u64; digest::MAX_CHAINING_LEN / 8],
            completed_data_blocks: u64,
            pending: [u8; digest::MAX_BLOCK_LEN],
            num_pending: usize,
            pub algorithm: &'static digest::Algorithm,
        }

        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(flip32(data.as_mut()));

        let mut state = [0u32; 8];
        state.copy_from_slice(
            unsafe { &transmute::<_, [u32; 16]>(transmute::<_, Context>(ctx).state)[..8] }
        );
        assert_eq!(sha256.state(), state);
    }
}
