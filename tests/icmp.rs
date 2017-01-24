extern crate pnet;
extern crate ipnetwork;
extern crate rips;

use ipnetwork::Ipv4Network;

use pnet::packet::Packet;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::ipv4::Ipv4Packet;

use rips::{Payload, CustomPayload};
use rips::ethernet::{EthernetBuilder, MacAddr};
use rips::icmp::{IcmpFields, IcmpBuilder, IcmpListener, IcmpTypes, EchoCodes};
use rips::ipv4::{Ipv4Builder, IpNextHeaderProtocols};
use rips::testing;

use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, Duration};

#[derive(Clone)]
pub struct MockIcmpListener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl IcmpListener for MockIcmpListener {
    fn recv(&mut self, _time: SystemTime, packet: &Ipv4Packet) {
        println!("MockIcmpListener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
    }
}

#[test]
fn recv_icmp() {
    let remote_mac = MacAddr::new(0, 0, 0, 0, 0, 0);
    let local_mac = remote_mac;
    let remote_ip = Ipv4Addr::new(10, 1, 2, 3);
    let local_ip = Ipv4Addr::new(10, 0, 0, 2);
    let local_net = Ipv4Network::new(local_ip, 24).unwrap();

    let (tx, rx) = mpsc::channel();
    let listener = MockIcmpListener { tx: tx };

    let (mut stack, interface, inject_handle, _) = testing::dummy_stack();
    stack.add_ipv4(&interface, local_net).unwrap();
    stack.icmp_listen(local_ip, IcmpTypes::EchoRequest, listener).unwrap();

    let data = &[6, 5];
    let mut payload = CustomPayload::new(IcmpFields::echo_request(), data);
    let mut icmp_builder = IcmpBuilder::new(&mut payload);
    let mut ipv4_builder = Ipv4Builder::new(remote_ip, local_ip, 1500, &mut icmp_builder);
    let mut eth_builder = EthernetBuilder::new(remote_mac, local_mac, &mut ipv4_builder);
    let mut buffer = vec![0; eth_builder.packet_size()];
    eth_builder.build(&mut buffer);

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
    thread::sleep(Duration::from_millis(100));

    let pkg = rx.try_recv().expect("No packet received");
    let ip_pkg = Ipv4Packet::new(&pkg[..]).unwrap();
    assert_eq!(ip_pkg.get_source(), remote_ip);
    assert_eq!(ip_pkg.get_destination(), local_ip);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Icmp);
    let icmp_pkg = EchoRequestPacket::new(ip_pkg.payload()).unwrap();
    assert_eq!(icmp_pkg.get_icmp_type(), IcmpTypes::EchoRequest);
    assert_eq!(EchoCodes::NoCode, icmp_pkg.get_icmp_code());
}
