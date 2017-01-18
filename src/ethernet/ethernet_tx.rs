use {Payload, Tx, TxResult};

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};

use super::{MacAddr, EtherType};

#[derive(Clone, Copy)]
pub struct EthernetFields(pub EtherType);


#[derive(Clone)]
pub struct EthernetTx<T> {
    tx: T,
    src: MacAddr,
    dst: MacAddr,
}

impl<T> EthernetTx<T> {
    pub fn new(src: MacAddr, dst: MacAddr, tx: T) -> Self {
        EthernetTx {
            tx: tx,
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
}

impl<T: Tx<()>> Tx<EthernetFields> for EthernetTx<T> {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<EthernetFields>
    {
        let mut builder = EthernetBuilder::new(self.src, self.dst, payload);
        self.tx.send(&mut builder)
    }
}


pub struct EthernetBuilder<'p, P: Payload<EthernetFields> + 'p> {
    src: MacAddr,
    dst: MacAddr,
    payload: &'p mut P,
}

impl<'p, P: Payload<EthernetFields>> EthernetBuilder<'p, P> {
    pub fn new(src: MacAddr, dst: MacAddr, payload: &'p mut P) -> Self {
        EthernetBuilder {
            src: src,
            dst: dst,
            payload: payload,
        }
    }
}

impl<'p, P: Payload<EthernetFields>> Payload<()> for EthernetBuilder<'p, P> {
    fn fields(&self) -> &() {
        static FIELDS: () = ();
        &FIELDS
    }

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
        pkg.set_ethertype(self.payload.fields().0);
        self.payload.build(pkg.payload_mut());
    }
}


#[cfg(test)]
mod ethernet_tx_tests {
    use {TxResult, TxError, Tx, Payload, CustomPayload};

    use pnet::packet::Packet;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::util::MacAddr;

    use std::error::Error;
    use std::sync::mpsc::{self, Sender, Receiver};

    use super::*;

    lazy_static! {
        static ref SRC: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 1);
        static ref DST: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 2);
    }

    #[test]
    fn src_dst() {
        let testee = EthernetTx::new(*SRC, *DST, ());
        assert_eq!(*SRC, testee.src());
        assert_eq!(*DST, testee.dst());
    }

    #[test]
    fn ethernet_builder() {
        let data = &[8, 7, 6];
        let mut payload = CustomPayload::new(EthernetFields(EtherTypes::Arp), data);

        let mut testee = EthernetBuilder::new(*SRC, *DST, &mut payload);

        assert_eq!(1, testee.num_packets());
        assert_eq!(17, testee.packet_size());
        let mut buffer = vec![0; 1024];
        testee.build(&mut buffer);

        let pkg = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(*SRC, pkg.get_source());
        assert_eq!(*DST, pkg.get_destination());
        assert_eq!(EtherTypes::Arp, pkg.get_ethertype());
        assert_eq!(data, &pkg.payload()[..3]);
    }
}
