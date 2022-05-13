use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::rdata::{DNSSECRData, DNSKEY, DS};
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;

#[derive(Debug, Clone)]
pub struct Nameserver {
    name: Name,
    addresses: Vec<IpAddr>,
}

impl Nameserver {
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.addresses.clone()
    }
}

type Nameservers = Vec<Nameserver>;

pub fn random_address(nameservers: Nameservers, mode: IpFamilyMode) -> Option<IpAddr> {
    for ns in nameservers {
        for addr in ns.addresses() {
            if mode == IpFamilyMode::Any {
                return Some(addr);
            }

            if addr.is_ipv4() && mode == IpFamilyMode::Ipv4 {
                return Some(addr);
            }

            if addr.is_ipv6() && mode == IpFamilyMode::Ipv6 {
                return Some(addr);
            }
        }
    }

    None
}

#[derive(Debug)]
pub struct Zone {
    name: Name,
    nameservers: Nameservers,
}

impl Zone {
    pub fn nameservers(&self) -> Vec<Nameserver> {
        self.nameservers.clone()
    }
}

fn to_ns(response: DnsResponse) -> Nameservers {
    let mut name_servers = vec![];

    for record in response
        .answers()
        .iter()
        .chain(response.name_servers())
    {
        if let Some(ns) = record.data().and_then(RData::as_ns) {
            let addrs = response
                .additionals()
                .iter()
                .filter(|x| x.name() == ns)
                .filter_map(into_address)
                .collect::<Vec<IpAddr>>();

            name_servers.push(Nameserver {
                name: ns.clone(),
                addresses: addrs,
            });
        }
    }

    name_servers
}

fn into_address(record: &Record) -> Option<IpAddr> {
    let data = record.data()?;
    match record.record_type() {
        RecordType::A => Some(IpAddr::V4(*data.as_a().unwrap())),
        RecordType::AAAA => Some(IpAddr::V6(*data.as_aaaa().unwrap())),
        _ => None,
    }
}

pub enum Trust {
    Trusted,
    Untrusted(String),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IpFamilyMode {
    Any,
    Ipv4,
    Ipv6,
}

impl FromStr for IpFamilyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => Ok(IpFamilyMode::Any),
            "ipv4" => Ok(IpFamilyMode::Ipv4),
            "ipv6" => Ok(IpFamilyMode::Ipv6),
            _ => Err("could not parse ip family mode".to_string()),
        }
    }
}

impl fmt::Display for IpFamilyMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            IpFamilyMode::Any => f.write_str("any"),
            IpFamilyMode::Ipv4 => f.write_str("ipv4"),
            IpFamilyMode::Ipv6 => f.write_str("ipv6"),
        }
    }
}

pub struct Querier {
    af_mode: IpFamilyMode,
}

impl Querier {
    pub fn new(af_mode: IpFamilyMode) -> Querier {
        Querier { af_mode }
    }

    pub fn query_zone(&self, name: Name, address: SocketAddr) -> Zone {
        let conn = UdpClientConnection::new(address).unwrap();
        let client = SyncClient::new(conn);
        let ns: DnsResponse = client.query(&name, DNSClass::IN, RecordType::NS).unwrap();

        Zone {
            name,
            nameservers: to_ns(ns),
        }
    }

    pub fn query_trust(&self, parent: &Zone, child: &Zone) -> Result<Trust, String> {
        let ds_records = self.query_ds(parent, child.name.clone())?;
        let dnskey_records = self.query_dnskey(child)?;

        for ds in ds_records {
            for dnskey in dnskey_records.iter() {
                if ds.key_tag() == dnskey.calculate_key_tag().unwrap()
                    && ds.algorithm() == dnskey.algorithm()
                {
                    return Ok(Trust::Trusted);
                }
            }
        }

        Ok(Trust::Untrusted("missing DS".to_string()))
    }

    fn query_ds(&self, parent: &Zone, child: Name) -> Result<Vec<DS>, String> {
        if let Some(parent_addr) = random_address(parent.nameservers(), self.af_mode) {
            let sock = SocketAddr::new(parent_addr, 53);
            let conn = UdpClientConnection::new(sock).unwrap();
            let client = SyncClient::new(conn);
            let ds: DnsResponse = client.query(&child, DNSClass::IN, RecordType::DS).unwrap();

            return Ok(ds
                .answers()
                .iter()
                .map(|x| {
                    x.data()
                        .and_then(RData::as_dnssec)
                        .and_then(DNSSECRData::as_ds)
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<DS>>());
        }

        Err("no name server address found".to_string())
    }

    fn query_dnskey(&self, child: &Zone) -> Result<Vec<DNSKEY>, String> {
        if let Some(child_addr) = random_address(child.nameservers(), self.af_mode) {
            let sock = SocketAddr::new(child_addr, 53);
            let conn = UdpClientConnection::new(sock).unwrap();
            let client = SyncClient::new(conn);
            let dnskey: DnsResponse = client
                .query(&child.name, DNSClass::IN, RecordType::DNSKEY)
                .unwrap();

            return Ok(dnskey
                .answers()
                .iter()
                .map(|x| {
                    x.data()
                        .and_then(RData::as_dnssec)
                        .and_then(DNSSECRData::as_dnskey)
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<DNSKEY>>());
        }

        Err("no name server address found".to_string())
    }
}
