extern crate pnet;
extern crate rips;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use rips::CustomPayload;
use rips::ethernet::{MacAddr, EthernetFields};
use rips::testing;

#[test]
fn test_ethernet_send() {
    let (mut stack, interface, _, read_handle) = testing::dummy_stack();
    let stack_interface = stack.interface(&interface).unwrap();
    let src = interface.mac;
    let dst = MacAddr::new(6, 7, 8, 9, 10, 11);

    let mut ethernet_sender = stack_interface.ethernet_sender(dst);
    let data = &[57];
    let payload = CustomPayload::new(EthernetFields(EtherTypes::Rarp), data);

    ethernet_sender.send(payload).expect("Not able to send");

    let sent_buffer = read_handle.try_recv().expect("No packet on dummy network");
    assert_eq!(sent_buffer.len(), 15);
    let sent_pkg = EthernetPacket::new(&sent_buffer).unwrap();
    assert_eq!(src, sent_pkg.get_source());
    assert_eq!(dst, sent_pkg.get_destination());
    assert_eq!(EtherTypes::Rarp, sent_pkg.get_ethertype());
    assert_eq!([57], sent_pkg.payload());
}
