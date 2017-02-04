use Interface;

use ipnetwork::Ipv4Network;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

// TODO: Add metric
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub net: Ipv4Network,
    pub gw: Option<Ipv4Addr>,
    pub interface: Interface,
}

impl RouteEntry {
    pub fn new(net: Ipv4Network, gw: Option<Ipv4Addr>, interface: Interface) -> Self {
        RouteEntry {
            net: net,
            gw: gw,
            interface: interface,
        }
    }
}

#[derive(Default)]
pub struct RoutingTable {
    table: BTreeMap<u8, Vec<RouteEntry>>,
}

impl RoutingTable {
    pub fn new() -> RoutingTable {
        RoutingTable { table: BTreeMap::new() }
    }

    // TODO: Check for collision
    // TODO: Increment Tx version counter
    pub fn add_route(&mut self, net: Ipv4Network, gw: Option<Ipv4Addr>, interface: Interface) {
        let prefix = net.prefix();
        let entry = RouteEntry::new(net, gw, interface);
        self.table.entry(prefix).or_insert_with(Vec::new).push(entry);
    }

    pub fn route(&self, ip: Ipv4Addr) -> Option<(Option<Ipv4Addr>, Interface)> {
        for (_prefix, entries) in self.table.iter().rev() {
            for entry in entries {
                if entry.net.contains(ip) {
                    return Some((entry.gw, entry.interface.clone()));
                }
            }
        }
        None
    }

    pub fn get_entries(&self) -> Vec<RouteEntry> {
        self.table.values().fold(Vec::new(), |mut vec, entry| {
            vec.extend_from_slice(entry);
            vec
        })
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use Interface;

    use ipnetwork::Ipv4Network;
    use pnet::util::MacAddr;

    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn empty() {
        let table = RoutingTable::new();
        assert!(table.route(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(table.route(Ipv4Addr::new(0, 0, 0, 0)).is_none());
    }

    #[test]
    fn no_default() {
        let mut table = RoutingTable::new();
        table.add_route(Ipv4Network::from_str("10/8").unwrap(), None, iface("eth0"));
        let (gw, out_eth) = table.route(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        assert_eq!(gw, None);
        assert_eq!(out_eth, iface("eth0"));
        assert!(table.route(Ipv4Addr::new(192, 168, 0, 0)).is_none());
    }

    #[test]
    fn with_default() {
        let gw = Ipv4Addr::new(10, 0, 0, 1);

        let mut table = RoutingTable::new();
        table.add_route(Ipv4Network::from_str("10/16").unwrap(), None, iface("eth0"));
        table.add_route(Ipv4Network::from_str("0/0").unwrap(),
                        Some(gw),
                        iface("eth1"));

        let (out_gw, out_eth) = table.route(Ipv4Addr::new(10, 0, 200, 20)).unwrap();
        assert_eq!(out_gw, None);
        assert_eq!(out_eth, iface("eth0"));
        let (out_gw2, out_eth2) = table.route(Ipv4Addr::new(192, 168, 0, 0)).unwrap();
        assert_eq!(out_gw2, Some(gw));
        assert_eq!(out_eth2, iface("eth1"));
    }

    #[test]
    fn with_specific() {
        let gw = Ipv4Addr::new(10, 0, 0, 1);

        let mut table = RoutingTable::new();
        table.add_route(Ipv4Network::from_str("10.0.0.0/24").unwrap(),
                        None,
                        iface("eth0"));
        table.add_route(Ipv4Network::from_str("10.0.0.99/32").unwrap(),
                        Some(gw),
                        iface("eth1"));

        let (out_gw, out_eth) = table.route(Ipv4Addr::new(10, 0, 0, 20)).unwrap();
        assert_eq!(out_gw, None);
        assert_eq!(out_eth, iface("eth0"));
        let (out_gw2, out_eth2) = table.route(Ipv4Addr::new(10, 0, 0, 99)).unwrap();
        assert_eq!(out_gw2, Some(gw));
        assert_eq!(out_eth2, iface("eth1"));
    }

    #[test]
    fn get_entries_empty() {
        let mut table = RoutingTable::new();
        assert!(table.get_entries().is_empty());
    }

    #[test]
    fn get_entries_one() {
        let mut table = RoutingTable::new();
        let net = Ipv4Network::from_str("10/16").unwrap();
        let gw = None;
        let iface = iface("eth0");

        table.add_route(net, gw, iface.clone());
        let mut entries = table.get_entries();
        assert_eq!(1, entries.len());
        let entry = entries.pop().unwrap();
        assert_eq!(net, entry.net);
        assert_eq!(gw, entry.gw);
        assert_eq!(iface, entry.interface);
    }

    fn iface(name: &str) -> Interface {
        Interface {
            name: name.to_string(),
            mac: MacAddr::new(0, 0, 0, 0, 0, 0),
        }
    }
}
