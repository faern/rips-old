extern crate rips;
extern crate pnet;
extern crate ipnetwork;
#[macro_use]
extern crate lazy_static;

use ipnetwork::Ipv4Network;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};

use rips::{rx, NetworkStack, DatalinkTx, CustomPayload, Tx};
use rips::ethernet::{EthernetRx, EthernetTx, MacAddr, EtherTypes};
use rips::ipv4::{BasicIpv4Listener, Ipv4Fields, Ipv4Rx, Ipv4Tx, IpNextHeaderProtocols};

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;

mod helper;

lazy_static! {
    static ref SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    static ref LAN_DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    static ref LAN_DST_MAC: MacAddr = MacAddr::new(9, 0, 0, 4, 0, 0);
}

#[test]
fn simple_send() {
    let mut dummy = dummy_ipv4_tx(*LAN_DST_IP, *LAN_DST_MAC);

    let data = &[100, 99];
    let mut payload = CustomPayload::new(Ipv4Fields(IpNextHeaderProtocols::Igmp), data);
    dummy.tx.send(&mut payload).unwrap().expect("Error while sending");

    let pkg = dummy.read_handle.try_recv().unwrap();

    let eth_pkg = EthernetPacket::new(&pkg).unwrap();
    assert_eq!(eth_pkg.get_destination(), *LAN_DST_MAC);
    assert_eq!(eth_pkg.get_ethertype(), EtherTypes::Ipv4);

    let ip_pkg = Ipv4Packet::new(eth_pkg.payload()).unwrap();
    assert_eq!(ip_pkg.get_version(), 4);
    assert_eq!(ip_pkg.get_source(), *SRC_IP);
    assert_eq!(ip_pkg.get_destination(), *LAN_DST_IP);
    assert_eq!(IpNextHeaderProtocols::Igmp,
               ip_pkg.get_next_level_protocol());
    assert_eq!(ip_pkg.payload(), [100, 99]);
}

struct DummyIpv4Tx {
    _stack: NetworkStack,
    tx: Ipv4Tx<EthernetTx<DatalinkTx>>,
    read_handle: Receiver<Box<[u8]>>,
}

fn dummy_ipv4_tx(dst_ip: Ipv4Addr, dst_mac: MacAddr) -> DummyIpv4Tx {
    let mut dummy = helper::dummy_stack();
    dummy.stack.interface(&dummy.interface).unwrap().arp_table().insert(dst_ip, dst_mac);

    let net = Ipv4Network::new(*SRC_IP, 24).unwrap();
    dummy.stack.add_ipv4(&dummy.interface, net).unwrap();
    let ipv4_tx = dummy.stack.ipv4_tx(dst_ip).unwrap();

    DummyIpv4Tx {
        _stack: dummy.stack,
        tx: ipv4_tx,
        read_handle: dummy.read_handle,
    }
}

// TODO: Deprecate or change this test. It does not test the stack at all, just
// individual components, which should be done in unit tests.
// If the stack get support for adding custom IPv4 listeners this test can be
// retained and adapted to that.
#[test]
fn custom_igmp_recv() {
    let (tx, rx) = mpsc::channel();
    let ipv4_listener = BasicIpv4Listener::new(tx);
    let mut ipv4_ip_listeners = HashMap::new();
    ipv4_ip_listeners.insert(IpNextHeaderProtocols::Igmp, ipv4_listener);

    let mut ipv4_listeners = HashMap::new();
    ipv4_listeners.insert(*LAN_DST_IP, ipv4_ip_listeners);

    let ipv4_rx = Ipv4Rx::new(Arc::new(Mutex::new(ipv4_listeners)));
    let ethernet_rx = EthernetRx::new(vec![ipv4_rx]);
    let dummy = helper::dummy_ethernet();
    rx::spawn(dummy.channel.receiver, ethernet_rx);

    let size = EthernetPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size() + 2;
    let mut buffer = vec![0; size];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Ipv4);
        let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        ip_pkg.set_header_length(5); // 5 is for no option fields
        ip_pkg.set_source(*SRC_IP);
        ip_pkg.set_destination(*LAN_DST_IP);
        ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Igmp);
        ip_pkg.set_total_length(20 + 2);
        ip_pkg.set_payload(&[67, 99]);
        let csum = checksum(&ip_pkg.to_immutable());
        ip_pkg.set_checksum(csum);
    }

    dummy.inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
    thread::sleep(Duration::new(1, 0));

    let (_time, ip_pkg) = rx.try_recv().unwrap();
    assert_eq!(ip_pkg.get_source(), *SRC_IP);
    assert_eq!(ip_pkg.get_destination(), *LAN_DST_IP);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Igmp);
    assert_eq!(ip_pkg.payload(), [67, 99]);
}
