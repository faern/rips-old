use {Payload, HasPayload, BasicPayload};

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};

use super::{MacAddr, EtherType};

/// Trait for anything wishing to be the payload of an Ethernet frame.
pub trait EthernetPayload: Payload {
    fn ether_type(&self) -> EtherType;
}


/// Basic reference implementation of an `EthernetPayload`.
/// Can be used to construct Ethernet frames with arbitrary payload from a
/// vector.
#[derive(Clone)]
pub struct BasicEthernetPayload<'a> {
    ether_type: EtherType,
    payload: BasicPayload<'a>,
}

impl<'a> BasicEthernetPayload<'a> {
    pub fn new(ether_type: EtherType, payload: &'a [u8]) -> Self {
        BasicEthernetPayload {
            ether_type: ether_type,
            payload: BasicPayload::new(payload),
        }
    }
}

impl<'a> EthernetPayload for BasicEthernetPayload<'a> {
    fn ether_type(&self) -> EtherType {
        self.ether_type
    }
}

impl<'a> HasPayload for BasicEthernetPayload<'a> {
    fn get_payload(&self) -> &Payload {
        &self.payload
    }

    fn get_payload_mut(&mut self) -> &mut Payload {
        &mut self.payload
    }
}

#[cfg(test)]
mod basic_ethernet_payload_tests {
    use Payload;
    use pnet::packet::ethernet::EtherTypes;
    use super::*;

    #[test]
    fn ether_type() {
        let testee = BasicEthernetPayload::new(EtherTypes::Ipv6, &[]);
        assert_eq!(EtherTypes::Ipv6, testee.ether_type());

        let testee = BasicEthernetPayload::new(EtherTypes::Arp, &[]);
        assert_eq!(EtherTypes::Arp, testee.ether_type());
    }
}

#[derive(Clone)]
pub struct EthernetTx {
    src: MacAddr,
    dst: MacAddr,
}

impl EthernetTx {
    pub fn new(src: MacAddr, dst: MacAddr) -> Self {
        EthernetTx {
            src: src,
            dst: dst,
        }
    }

    pub fn src(&self) -> MacAddr {
        self.src
    }

    pub fn dst(&self) -> MacAddr {
        self.dst
    }

    pub fn send<P: EthernetPayload>(&mut self, payload: P) -> EthernetBuilder<P> {
        EthernetBuilder::new(self.src, self.dst, payload)
    }
}


/// Struct building Ethernet frames
pub struct EthernetBuilder<P: EthernetPayload> {
    src: MacAddr,
    dst: MacAddr,
    payload: P,
}

impl<P: EthernetPayload> EthernetBuilder<P> {
    /// Creates a new `EthernetBuilder` with the given parameters
    pub fn new(src: MacAddr, dst: MacAddr, payload: P) -> Self {
        EthernetBuilder {
            src: src,
            dst: dst,
            payload: payload,
        }
    }
}

impl<P: EthernetPayload> Payload for EthernetBuilder<P> {
    fn num_packets(&self) -> usize {
        self.payload.num_packets()
    }

    fn packet_size(&self) -> usize {
        EthernetPacket::minimum_packet_size() + self.payload.packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableEthernetPacket::new(buffer).unwrap();
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_ethertype(self.payload.ether_type());
        self.payload.build(pkg.payload_mut());
    }
}


#[cfg(test)]
mod ethernet_tx_tests {
    use {TxResult, TxError, Tx, Payload};

    use pnet::packet::Packet;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::util::MacAddr;

    use std::error::Error;
    use std::sync::mpsc::{self, Sender, Receiver};

    use super::*;

    // pub struct MockTx {
    //     chan: Sender<Box<[u8]>>,
    // }

    // impl MockTx {
    //     pub fn new() -> (Self, Receiver<Box<[u8]>>) {
    //         let (tx, rx) = mpsc::channel();
    //         (MockTx { chan: tx }, rx)
    //     }
    // }

    // impl Tx for MockTx {
    //     fn send<P: Payload>(&mut self, mut payload: P) -> TxResult<()> {
    //         for _ in 0..payload.num_packets() {
    //             let mut buffer = vec![0; payload.packet_size()];
    //             payload.build(&mut buffer);
    //             self.chan
    //                 .send(buffer.into_boxed_slice())
    //                 .map_err(|e| TxError::Other(e.description().to_owned()))?;
    //         }
    //         Ok(())
    //     }
    // }

    lazy_static! {
        static ref SRC: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 1);
        static ref DST: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 2);
    }

    #[test]
    fn src_dst() {
        let testee = EthernetTx::new(*SRC, *DST);
        assert_eq!(*SRC, testee.src());
        assert_eq!(*DST, testee.dst());
    }

    #[test]
    fn send() {
        let data = &[8, 7, 6];
        let payload = BasicEthernetPayload::new(EtherTypes::Arp, data);

        let mut testee = EthernetTx::new(*SRC, *DST);
        let mut ethernet_builder = testee.send(payload);

        assert_eq!(1, ethernet_builder.num_packets());
        assert_eq!(17, ethernet_builder.packet_size());
        let mut buffer = vec![0; 1024];
        ethernet_builder.build(&mut buffer);

        let pkg = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(*SRC, pkg.get_source());
        assert_eq!(*DST, pkg.get_destination());
        assert_eq!(EtherTypes::Arp, pkg.get_ethertype());
        assert_eq!(data, &pkg.payload()[..3]);
    }
}
