extern crate rips;
extern crate pnet;
#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate lazy_static;
extern crate ipnetwork;

use ipnetwork::Ipv4Network;

use rips::{Tx, CustomPayload};
use rips::ethernet::{EthernetFields, EtherTypes, MacAddr};

use std::net::Ipv4Addr;

mod helper;

lazy_static! {
    static ref DST_MAC: MacAddr = MacAddr(0, 0, 0, 0, 0, 0);
    static ref DEFAULT_ROUTE: Ipv4Network = Ipv4Network::new(Ipv4Addr::new(0, 0,0,0), 0).unwrap();
}

#[test]
fn routing_table_change_invalidate_tx() {
    let dummy = helper::dummy_stack();
    let mut testee = dummy.stack;
    let mut tx = testee.interface(&dummy.interface).unwrap().ethernet_tx(*DST_MAC);

    let mut payload = CustomPayload::new(EthernetFields(EtherTypes::Arp), &[]);
    assert_matches!(tx.send(&mut payload), Some(Ok(())));
    {
        let mut routing_table = testee.routing_table();
        routing_table.add_route(*DEFAULT_ROUTE, None, dummy.interface.clone());
    }
    assert_matches!(tx.send(&mut payload), None);
}
