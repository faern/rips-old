use {Payload, TxResult, Tx};
use ethernet::{EtherTypes, MacAddr, EthernetFields};

use pnet::packet::arp::{ArpHardwareTypes, ArpPacket, MutableArpPacket};
pub use pnet::packet::arp::{ArpOperation, ArpOperations};

use std::net::Ipv4Addr;

pub struct ArpPayload {
    pub operation: ArpOperation,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPayload {
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpPayload {
            operation: ArpOperations::Request,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: MacAddr(0, 0, 0, 0, 0, 0),
            target_ip: target_ip,
        }
    }

    pub fn reply(sender_mac: MacAddr,
                 sender_ip: Ipv4Addr,
                 target_mac: MacAddr,
                 target_ip: Ipv4Addr)
                 -> Self {
        ArpPayload {
            operation: ArpOperations::Reply,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: target_mac,
            target_ip: target_ip,
        }
    }
}

impl Payload<ArpPayload> for ArpPayload {
    fn fields(&self) -> &Self {
        &self
    }
    fn num_packets(&self) -> usize {
        1
    }
    fn packet_size(&self) -> usize {
        0
    }
    fn build(&mut self, _buffer: &mut [u8]) {}
}

#[derive(Clone)]
pub struct ArpTx<T> {
    tx: T,
}

impl<T> ArpTx<T> {
    pub fn new(tx: T) -> Self {
        ArpTx { tx: tx }
    }
}

impl<T: Tx<EthernetFields>> Tx<ArpPayload> for ArpTx<T> {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<ArpPayload>
    {
        let mut builder = ArpBuilder::new(payload);
        self.tx.send(&mut builder)
    }
}

pub struct ArpBuilder<'p, P: Payload<ArpPayload> + 'p> {
    payload: &'p mut P,
}

impl<'p, P: Payload<ArpPayload>> ArpBuilder<'p, P> {
    pub fn new(payload: &'p mut P) -> Self {
        ArpBuilder { payload: payload }
    }
}

impl<'p, P: Payload<ArpPayload>> Payload<EthernetFields> for ArpBuilder<'p, P> {
    fn fields(&self) -> &EthernetFields {
        static FIELDS: EthernetFields = EthernetFields(EtherTypes::Arp);
        &FIELDS
    }

    fn num_packets(&self) -> usize {
        1
    }

    fn packet_size(&self) -> usize {
        ArpPacket::minimum_packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut arp_pkg = MutableArpPacket::new(buffer).unwrap();
        arp_pkg.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkg.set_protocol_type(EtherTypes::Ipv4);
        arp_pkg.set_hw_addr_len(6);
        arp_pkg.set_proto_addr_len(4);
        arp_pkg.set_operation(self.payload.fields().operation);
        arp_pkg.set_sender_hw_addr(self.payload.fields().sender_mac);
        arp_pkg.set_sender_proto_addr(self.payload.fields().sender_ip);
        arp_pkg.set_target_hw_addr(self.payload.fields().target_mac);
        arp_pkg.set_target_proto_addr(self.payload.fields().target_ip);
    }
}
