#![allow(clippy::upper_case_acronyms, clippy::vec_init_then_push)]

mod dnscrypt;
mod dnscrypt_relay;
mod doh;
mod odoh;

use std::io::{self, Write};

pub use self::dnscrypt::*;
pub use self::dnscrypt_relay::*;
pub use self::doh::*;
pub use self::odoh::*;

pub enum InformalProperty {
    DNSSEC,
    NoLogs,
    NoFilters,
}

impl From<InformalProperty> for u64 {
    fn from(informal_property: InformalProperty) -> u64 {
        match informal_property {
            InformalProperty::DNSSEC => 0x01,
            InformalProperty::NoLogs => 0x02,
            InformalProperty::NoFilters => 0x04,
        }
    }
}

pub trait WithInformalProperty {
    fn with_informal_property(self, informal_property: InformalProperty) -> Self;
}

fn lp_encode<W: Write>(writer: &mut W, string: &[u8]) -> io::Result<()> {
    let mut encoded = vec![];
    let len = string.len();
    assert!(len <= 0xff);
    encoded.push(len as u8);
    encoded.extend(string);
    writer.write_all(&encoded)
}

fn vlp_encode<W: Write>(writer: &mut W, strings: &[Vec<u8>]) -> io::Result<()> {
    if strings.is_empty() {
        return writer.write_all(&[0u8]);
    }
    let mut encoded = vec![];
    let mut it = strings.iter();
    let mut next = it.next();
    while let Some(string) = next {
        next = it.next();
        let len = string.len();
        assert!(len < 0x80);
        match next {
            None => encoded.push(len as u8),
            _ => encoded.push(0x80 | len as u8),
        };
        encoded.extend(&string[..]);
    }
    writer.write_all(&encoded)
}

#[test]
fn test_doh() {
    let b = DoHBuilder::new("example.com".to_owned(), "/dns".to_owned())
        .with_address("127.0.0.1:443".to_string())
        .with_informal_property(InformalProperty::DNSSEC)
        .serialize()
        .unwrap();
    assert_eq!(
        b,
        "sdns://AgEAAAAAAAAADTEyNy4wLjAuMTo0NDMAC2V4YW1wbGUuY29tBC9kbnM",
    )
}
