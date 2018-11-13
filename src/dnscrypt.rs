use byteorder::{LittleEndian, WriteBytesExt};
use crate::{lp_encode, vlp_encode, InformalProperty, WithInformalProperty};
use std::io;

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
        let provider_bin = {
            let mut bin = vec![];
            bin.extend(&self.provider.pk);
            bin.extend(self.provider.name.as_str().as_bytes());
            bin
        };
        lp_encode(&mut bin, &provider_bin)?;
        let serialized = base64::encode_config(
            &bin,
            base64::Config::new(base64::CharacterSet::UrlSafe, false),
        );
        Ok(format!("sdns://{}", serialized))
    }
}

impl WithInformalProperty for DNSCryptBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}
