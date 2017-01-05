use {Payload, TxResult, DatalinkTx, Tx};
use ethernet::{EtherType, EtherTypes, MacAddr};
use ethernet::{EthernetPayload, EthernetTx};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket, MutableArpPacket};

use std::net::Ipv4Addr;

pub trait ArpPayload {
    fn operation(&self) -> ArpOperation;
    fn sender_mac(&self) -> MacAddr;
    fn sender_ip(&self) -> Ipv4Addr;
    fn target_mac(&self) -> MacAddr;
    fn target_ip(&self) -> Ipv4Addr;
}

pub struct ArpRequest {
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

impl ArpRequest {
    pub fn new(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpRequest {
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_ip: target_ip,
        }
    }
}

impl ArpPayload for ArpRequest {
    fn operation(&self) -> ArpOperation {
        ArpOperations::Request
    }

    fn sender_mac(&self) -> MacAddr {
        self.sender_mac
    }

    fn sender_ip(&self) -> Ipv4Addr {
        self.sender_ip
    }

    fn target_mac(&self) -> MacAddr {
        MacAddr(0, 0, 0, 0, 0, 0)
    }

    fn target_ip(&self) -> Ipv4Addr {
        self.target_ip
    }
}

pub struct ArpReply {
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

impl ArpReply {
    pub fn new(sender_mac: MacAddr,
               sender_ip: Ipv4Addr,
               target_mac: MacAddr,
               target_ip: Ipv4Addr)
               -> Self {
        ArpReply {
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: target_mac,
            target_ip: target_ip,
        }
    }
}

impl ArpPayload for ArpReply {
    fn operation(&self) -> ArpOperation {
        ArpOperations::Reply
    }

    fn sender_mac(&self) -> MacAddr {
        self.sender_mac
    }

    fn sender_ip(&self) -> Ipv4Addr {
        self.sender_ip
    }

    fn target_mac(&self) -> MacAddr {
        self.target_mac
    }

    fn target_ip(&self) -> Ipv4Addr {
        self.target_ip
    }
}


pub struct ArpTx(());

impl ArpTx {
    pub fn new() -> Self {
        ArpTx(())
    }

    pub fn send<'p, P: ArpPayload>(&self, payload: &'p mut P) -> ArpBuilder<'p, P> {
        ArpBuilder::new(payload)
    }
}

pub struct ArpBuilder<'p, P: ArpPayload + 'p> {
    payload: &'p mut P,
}

impl<'p, P: ArpPayload> ArpBuilder<'p, P> {
    pub fn new(payload: &'p mut P) -> Self {
        ArpBuilder { payload: payload }
    }
}

impl<'p, P: ArpPayload> EthernetPayload for ArpBuilder<'p, P> {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Arp
    }
}

impl<'p, P: ArpPayload> Payload for ArpBuilder<'p, P> {
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
        arp_pkg.set_operation(self.payload.operation());
        arp_pkg.set_sender_hw_addr(self.payload.sender_mac());
        arp_pkg.set_sender_proto_addr(self.payload.sender_ip());
        arp_pkg.set_target_hw_addr(self.payload.target_mac());
        arp_pkg.set_target_proto_addr(self.payload.target_ip());
    }
}
