use std::io;

use byteorder::{LittleEndian, WriteBytesExt};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use crate::{lp_encode, vlp_encode, InformalProperty, WithInformalProperty};

#[derive(Default, Debug)]
pub struct DNSCryptProvider {
    name: String,
    pk: Vec<u8>,
}

impl DNSCryptProvider {
    pub fn new(name: String, pk: Vec<u8>) -> Self {
        DNSCryptProvider { name, pk }
    }
}

#[derive(Default, Debug)]
pub struct DNSCryptBuilder {
    informal_properties: u64,
    addrs: Vec<String>,
    provider: DNSCryptProvider,
}

impl DNSCryptBuilder {
    pub fn new(provider: DNSCryptProvider) -> Self {
        DNSCryptBuilder {
            informal_properties: 0,
            addrs: vec![],
            provider,
        }
    }

    pub fn with_addr(mut self, addr: String) -> Self {
        self.addrs.push(addr);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        if port == 443 {
            return self;
        }
        self.addrs = self
            .addrs
            .iter()
            .map(|addr| format!("{}:{}", addr, port))
            .collect();
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x01);
        bin.write_u64::<LittleEndian>(self.informal_properties)?;
        let addrs_bin: Vec<_> = self
            .addrs
            .iter()
            .map(|addr| addr.as_bytes().to_vec())
            .collect();
        vlp_encode(&mut bin, &addrs_bin)?;
        lp_encode(&mut bin, &self.provider.pk)?;
        lp_encode(&mut bin, self.provider.name.as_str().as_bytes())?;
        let serialized = Base64UrlSafeNoPadding::encode_to_string(bin).unwrap();
        Ok(format!("sdns://{}", serialized))
    }
}

impl WithInformalProperty for DNSCryptBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}
