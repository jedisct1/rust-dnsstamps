use crate::{lp_encode, vlp_encode, InformalProperty, WithInformalProperty};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io;

#[derive(Default, Debug)]
pub struct DoHBuilder {
    informal_properties: u64,
    addrs: Vec<String>,
    hashes: Vec<Vec<u8>>,
    hostname: String,
    path: String,
    bootstrap_ips: Vec<String>,
}

impl DoHBuilder {
    pub fn new(hostname: String, path: String) -> Self {
        DoHBuilder {
            informal_properties: 0,
            addrs: vec![],
            hostname,
            path,
            hashes: vec![],
            bootstrap_ips: vec![],
        }
    }

    pub fn with_address(mut self, addr: String) -> Self {
        self.addrs.push(addr);
        self
    }

    pub fn with_cert_hash(mut self, hash: Vec<u8>) -> Self {
        self.hashes.push(hash);
        self
    }

    pub fn with_bootstrap_ip(mut self, ip: String) -> Self {
        self.bootstrap_ips.push(ip);
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x02);
        bin.write_u64::<LittleEndian>(self.informal_properties)?;
        let addrs_bin: Vec<_> = self
            .addrs
            .iter()
            .map(|addr| addr.as_bytes().to_vec())
            .collect();
        vlp_encode(&mut bin, &addrs_bin)?;
        vlp_encode(&mut bin, &self.hashes)?;
        lp_encode(&mut bin, &self.hostname.as_bytes())?;
        lp_encode(&mut bin, &self.path.as_bytes())?;
        if !self.bootstrap_ips.is_empty() {
            let bootstrap_ips_bin: Vec<_> = self
                .bootstrap_ips
                .iter()
                .map(|ip| ip.as_bytes().to_vec())
                .collect();
            vlp_encode(&mut bin, &bootstrap_ips_bin)?;
        }
        let serialized = base64::encode_config(
            &bin,
            base64::Config::new(base64::CharacterSet::UrlSafe, false),
        );
        Ok(format!("sdns://{}", serialized))
    }
}

impl WithInformalProperty for DoHBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}
