use std::env;
use std::fs;
use std::io::{self, Read};

use sha256::Sha256;

const BUFFER_SIZE: usize = 1024 * 16;

fn print_result(sum: &[u8], name: &str) {
    for b in sum {
        print!("{:02x}", b);
    }
    println!("  {}", name);
}

fn sha256sum<R: Read>(r: &mut R) -> [u8; 32] {
    let mut sha256 = Sha256::new();

    let mut buf = Vec::with_capacity(BUFFER_SIZE);
    unsafe {
        buf.set_len(BUFFER_SIZE);
    }

    let mut n;
    while {
        n = r.read(&mut buf[..BUFFER_SIZE]).unwrap();
        n > 0
    } {
        sha256.update(&buf[..n]);
    }

    sha256.finish()
}

fn main() {
    let args = env::args();

    if args.len() > 1 {
        let mut file;

        for path in args.skip(1) {
            file = fs::File::open(&path).unwrap();
            print_result(&sha256sum(&mut file), &path);
        }
    } else {
        let stdin = io::stdin();
        print_result(&sha256sum(&mut stdin.lock()), "-");
    }
}
