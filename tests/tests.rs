use std::fmt::Write;

use sha256::Sha256;

fn to_hex(data: &[u8; 32]) -> String {
    let mut hex = String::new();

    for &b in data {
        write!(hex, "{:02x}", b).unwrap();
    }

    hex
}

#[test]
fn t1() {
    let mut sha256 = Sha256::default();

    sha256.update("abc".as_bytes());
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
}

#[test]
fn t2() {
    let mut sha256 = Sha256::default();

    sha256.update("".as_bytes());
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
}

#[test]
fn t3() {
    let mut sha256 = Sha256::default();

    sha256.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )
}

#[test]
fn t4() {
    let mut sha256 = Sha256::default();

    sha256.update("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    )
}

#[test]
fn t5() {
    let mut sha256 = Sha256::default();

    for _ in 0..1000000 {
        sha256.update("a".as_bytes());
    }
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )
}

#[test]
fn t6() {
    let mut sha256 = Sha256::default();

    for _ in 0..16777216 {
        sha256
            .update("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".as_bytes());
    }
    assert_eq!(
        to_hex(&sha256.finish()).as_str(),
        "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
    )
}
