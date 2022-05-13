use std::io;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use crate::vlp_encode;

#[derive(Default, Debug)]
pub struct DNSCryptRelayBuilder {
    addrs: Vec<String>,
}

impl DNSCryptRelayBuilder {
    pub fn new() -> Self {
        DNSCryptRelayBuilder { addrs: vec![] }
    }

    pub fn with_addr(mut self, addr: String) -> Self {
        self.addrs.push(addr);
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x81);
        let addrs_bin: Vec<_> = self
            .addrs
            .iter()
            .map(|addr| addr.as_bytes().to_vec())
            .collect();
        vlp_encode(&mut bin, &addrs_bin)?;
        let serialized = Base64UrlSafeNoPadding::encode_to_string(bin).unwrap();
        Ok(format!("sdns://{}", serialized))
    }
}
