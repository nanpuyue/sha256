use std::env;
use std::fs::File;
use std::io::{stdin, Read};

use sha256::Sha256;

const BUFFER_SIZE: usize = 1024 * 16;

fn print_result(sum: &[u8], name: &str) {
    for b in sum {
        print!("{:02x}", b);
    }
    println!("  {}", name);
}

fn sha256sum<R: Read>(r: &mut R) -> [u8; 32] {
    let mut sha256 = Sha256::default();

    let mut buf = Vec::with_capacity(BUFFER_SIZE);
    unsafe {
        buf.set_len(BUFFER_SIZE);
    }

    let mut n;
    while {
        n = r.read(buf.as_mut()).unwrap();
        n > 0
    } {
        sha256.update(&buf[..n]);
    }

    sha256.finish()
}

fn main() {
    let args = env::args();

    if args.len() > 1 {
        for path in args.skip(1) {
            print_result(&sha256sum(&mut File::open(&path).unwrap()), &path);
        }
    } else {
        print_result(&sha256sum(&mut stdin().lock()), "-");
    }
}
