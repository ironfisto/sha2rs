fn main() {
    let input = b"mukul";

    // Initial SHA-224 hash values
    let mut h: [u32; 8] = [
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4,
    ];

    // Step 1: Pad the message
    let padded = pad_sha224(input);

    // Step 2: Process each 512-bit block
    for block in padded.chunks(64) {
        let w = create_schedule(block);

        // Working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // Step 3: Main compression loop
        for t in 0..64 {
            let t1 = add(
                add(
                    add(
                        add(hh, bsig1(e)),
                        choose(e, f, g),
                    ),
                    K[t],
                ),
                w[t],
            );

            let t2 = add(
                bsig0(a),
                majority(a, b, c),
            );

            hh = g;
            g = f;
            f = e;
            e = add(d, t1);
            d = c;
            c = b;
            b = a;
            a = add(t1, t2);
        }

        // Step 4: Update hash state
        h[0] = add(h[0], a);
        h[1] = add(h[1], b);
        h[2] = add(h[2], c);
        h[3] = add(h[3], d);
        h[4] = add(h[4], e);
        h[5] = add(h[5], f);
        h[6] = add(h[6], g);
        h[7] = add(h[7], hh);
    }

    // SHA-224 outputs only the first 7 words (28 bytes)
    for word in &h[..7] {
        print!("{:08x}", word);
    }
    println!();
}

fn create_schedule(block: &[u8]) -> [u32; 64] {
    let mut w = [0u32; 64];

    // W0..W15 come directly from the block
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[t * 4],
            block[t * 4 + 1],
            block[t * 4 + 2],
            block[t * 4 + 3],
        ]);
    }

    // W16..W63 will come next
    for t in 16..64 {
        w[t] = add(
            add(ssig1(w[t - 2]), w[t - 7]),
            add(ssig0(w[t - 15]), w[t - 16]),
        );
    }

    w
}


const K: [u32; 64] = [
    0x428a2f98, 0x71374491,
    0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d,
    0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb,
    0xbef9a3f7, 0xc67178f2,
];

fn and(x: u32, y: u32) -> u32 {
    x & y
}

fn or(x: u32, y: u32) -> u32 {
    x | y
}

fn xor(x: u32, y: u32) -> u32 {
    x ^ y
}

fn not(x: u32) -> u32 {
    !x
}

fn add(x: u32, y: u32) -> u32 {
    x.wrapping_add(y)
}

fn shift_right(x: u32, y: u32) -> u32 {
    x >> y
}

fn rotate_right(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn rotate_left(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn pad_sha224(input: &[u8]) -> Vec<u8> {
    let mut padded = input.to_vec();

    let bit_len = (input.len() as u64) * 8;

    // append the '1' bit
    padded.push(0x80);

    // pad with zeros until length ≡ 56 (mod 64)
    while padded.len() % 64 != 56 {
        padded.push(0);
    }

    // append original length (big-endian)
    padded.extend_from_slice(&bit_len.to_be_bytes());

    padded
}

fn choose(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    rotate_right(x, 2) ^
        rotate_right(x, 13) ^
        rotate_right(x, 22)
}

fn bsig1(x: u32) -> u32 {
    rotate_right(x, 6) ^
        rotate_right(x, 11) ^
        rotate_right(x, 25)
}

fn ssig0(x: u32) -> u32 {
    rotate_right(x, 7) ^
        rotate_right(x, 18) ^
        shift_right(x, 3)
}

fn ssig1(x: u32) -> u32 {
    rotate_right(x, 17) ^
        rotate_right(x, 19) ^
        shift_right(x, 10)
}