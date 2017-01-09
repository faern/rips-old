use {Payload, TxResult, DatalinkTx, Tx};
use ethernet::{EtherType, EtherTypes, MacAddr};
use ethernet::{EthernetFields, EthernetTx};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket, MutableArpPacket};

use std::net::Ipv4Addr;

pub struct ArpFields {
    pub operation: ArpOperation,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpFields {
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpFields {
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
        ArpFields {
            operation: ArpOperations::Reply,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: target_mac,
            target_ip: target_ip,
        }
    }
}


pub struct ArpTx(());

impl ArpTx {
    pub fn new() -> Self {
        ArpTx(())
    }

    pub fn send<'p, P>(&self, payload: &'p mut P) -> ArpBuilder<'p, P>
        where P: Payload<ArpFields>
    {
        ArpBuilder::new(payload)
    }
}


pub struct ArpBuilder<'p, P: Payload<ArpFields> + 'p> {
    payload: &'p mut P,
}

impl<'p, P: Payload<ArpFields>> ArpBuilder<'p, P> {
    pub fn new(payload: &'p mut P) -> Self {
        ArpBuilder { payload: payload }
    }
}

impl<'p, P: Payload<ArpFields>> Payload<EthernetFields> for ArpBuilder<'p, P> {
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
