use crate::vlp_encode;
use std::io;

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
        let serialized = base64::encode_config(
            &bin,
            base64::Config::new(base64::CharacterSet::UrlSafe, false),
        );
        Ok(format!("sdns://{}", serialized))
    }
}
