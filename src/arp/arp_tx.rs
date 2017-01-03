use {Payload, TxResult, DatalinkTx, Tx};
use ethernet::{EtherType, EtherTypes, MacAddr};
use ethernet::{EthernetPayload, EthernetTx, EthernetTxImpl};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket, MutableArpPacket};

use std::net::Ipv4Addr;

pub struct ArpProtocol {
    datalink: DatalinkTx,
    ethernet: EthernetTxImpl,
    arp_request: ArpRequestTx,
    arp_reply: ArpReplyTx,
}

impl ArpProtocol {
    pub fn new(datalink: DatalinkTx,
               ethernet: EthernetTxImpl,
               arp_request: ArpRequestTx,
               arp_reply: ArpReplyTx)
               -> Self {
        ArpProtocol {
            datalink: datalink,
            ethernet: ethernet,
            arp_request: arp_request,
            arp_reply: arp_reply,
        }
    }

    pub fn send_request(&mut self,
                        sender_mac: MacAddr,
                        sender_ip: Ipv4Addr,
                        target_ip: Ipv4Addr)
                        -> TxResult<()> {
        let arp_payload = self.arp_request.send(sender_mac, sender_ip, target_ip);
        let ethernet_payload = self.ethernet.send(arp_payload);
        self.datalink.send(ethernet_payload)
    }
}

pub struct ArpRequestTx(());

impl ArpRequestTx {
    pub fn new() -> Self {
        ArpRequestTx(())
    }

    /// Sends an Arp request packet to the network. More specifically Ipv4 to
    /// Ethernet request
    pub fn send(&mut self,
                sender_mac: MacAddr,
                sender_ip: Ipv4Addr,
                target_ip: Ipv4Addr)
                -> ArpBuilder {
        ArpBuilder::new_request(sender_mac, sender_ip, target_ip)
    }
}

pub struct ArpReplyTx {
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
}

impl ArpReplyTx {
    pub fn new(sender_mac: MacAddr, sender_ip: Ipv4Addr) -> Self {
        ArpReplyTx {
            sender_mac: sender_mac,
            sender_ip: sender_ip,
        }
    }

    pub fn send(&mut self, target_mac: MacAddr, target_ip: Ipv4Addr) -> ArpBuilder {
        ArpBuilder::new_reply(self.sender_mac, self.sender_ip, target_mac, target_ip)
    }
}

pub struct ArpBuilder {
    operation: ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

impl ArpBuilder {
    pub fn new_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpBuilder {
            operation: ArpOperations::Request,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: MacAddr::new(0, 0, 0, 0, 0, 0),
            target_ip: target_ip,
        }
    }

    pub fn new_reply(sender_mac: MacAddr,
                     sender_ip: Ipv4Addr,
                     target_mac: MacAddr,
                     target_ip: Ipv4Addr)
                     -> Self {
        ArpBuilder {
            operation: ArpOperations::Reply,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: target_mac,
            target_ip: target_ip,
        }
    }
}

impl EthernetPayload for ArpBuilder {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Arp
    }
}

impl Payload for ArpBuilder {
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
        arp_pkg.set_operation(self.operation);
        arp_pkg.set_sender_hw_addr(self.sender_mac);
        arp_pkg.set_sender_proto_addr(self.sender_ip);
        arp_pkg.set_target_hw_addr(self.target_mac);
        arp_pkg.set_target_proto_addr(self.target_ip);
    }
}
