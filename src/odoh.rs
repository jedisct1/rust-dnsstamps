use std::io;

use byteorder::{LittleEndian, WriteBytesExt};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use crate::{lp_encode, vlp_encode, InformalProperty, WithInformalProperty};

#[derive(Default, Debug)]
pub struct ODoHTargetBuilder {
    informal_properties: u64,
    hostname: String,
    port: Option<u16>,
    path: String,
}

impl ODoHTargetBuilder {
    pub fn new(hostname: String, path: String) -> Self {
        ODoHTargetBuilder {
            informal_properties: 0,
            hostname,
            port: None,
            path,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        if port == 443 {
            return self;
        }
        self.port = Some(port);
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x05);
        bin.write_u64::<LittleEndian>(self.informal_properties)?;

        let mut hostname_with_port = self.hostname.clone();
        if let Some(port) = self.port {
            hostname_with_port.push(':');
            hostname_with_port.push_str(&port.to_string());
        }

        lp_encode(&mut bin, hostname_with_port.as_bytes())?;
        lp_encode(&mut bin, self.path.as_bytes())?;
        let serialized = Base64UrlSafeNoPadding::encode_to_string(bin).unwrap();
        Ok(format!("sdns://{}", serialized))
    }
}

impl WithInformalProperty for ODoHTargetBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}

//

#[derive(Default, Debug)]
pub struct ODoHRelayBuilder {
    informal_properties: u64,
    addrs: Vec<String>,
    hashes: Vec<Vec<u8>>,
    hostname: String,
    port: Option<u16>,
    path: String,
    bootstrap_ips: Vec<String>,
}

impl ODoHRelayBuilder {
    pub fn new(hostname: String, path: String) -> Self {
        ODoHRelayBuilder {
            informal_properties: 0,
            addrs: vec![],
            hostname,
            port: None,
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

    pub fn with_port(mut self, port: u16) -> Self {
        if port == 443 {
            return self;
        }
        self.port = Some(port);
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x85);
        bin.write_u64::<LittleEndian>(self.informal_properties)?;

        let mut hostname_with_port = self.hostname.clone();
        if let Some(port) = self.port {
            hostname_with_port.push(':');
            hostname_with_port.push_str(&port.to_string());
        }

        let addrs_bin: Vec<_> = self
            .addrs
            .iter()
            .map(|addr| addr.as_bytes().to_vec())
            .collect();
        vlp_encode(&mut bin, &addrs_bin)?;
        vlp_encode(&mut bin, &self.hashes)?;
        lp_encode(&mut bin, hostname_with_port.as_bytes())?;
        lp_encode(&mut bin, self.path.as_bytes())?;
        if !self.bootstrap_ips.is_empty() {
            let bootstrap_ips_bin: Vec<_> = self
                .bootstrap_ips
                .iter()
                .map(|ip| ip.as_bytes().to_vec())
                .collect();
            vlp_encode(&mut bin, &bootstrap_ips_bin)?;
        }
        let serialized = Base64UrlSafeNoPadding::encode_to_string(bin).unwrap();
        Ok(format!("sdns://{}", serialized))
    }
}

impl WithInformalProperty for ODoHRelayBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}
