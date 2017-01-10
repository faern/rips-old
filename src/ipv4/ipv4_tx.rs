use {Payload, TxResult, Tx};
use ethernet::{EthernetFields, EtherTypes};

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};

use rand::thread_rng;
use std::cmp;
use std::net::Ipv4Addr;

use super::{MORE_FRAGMENTS, NO_FLAGS};

#[derive(Copy, Clone)]
pub struct Ipv4Fields(pub IpNextHeaderProtocol);

/// IPv4 packet builder and sender. Will fragment packets larger than the
/// MTU reported by the underlying `EthernetTx` given to the constructor.
#[derive(Clone)]
pub struct Ipv4Tx<T> {
    tx: T,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    mtu: usize,
}

impl<T> Ipv4Tx<T> {
    /// Constructs a new `Ipv4Tx`.
    ///
    /// # Panics
    ///
    /// Panics if `mtu` is smaller than the minimum Ipv4 packet size.
    pub fn new(tx: T, src: Ipv4Addr, dst: Ipv4Addr, mtu: usize) -> Self {
        assert!(mtu >= Ipv4Packet::minimum_packet_size());
        Ipv4Tx {
            tx: tx,
            src: src,
            dst: dst,
            mtu: mtu,
        }
    }

    pub fn src(&self) -> Ipv4Addr {
        self.src
    }

    pub fn dst(&self) -> Ipv4Addr {
        self.dst
    }
}

impl<T: Tx<EthernetFields>> Tx<Ipv4Fields> for Ipv4Tx<T> {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<Ipv4Fields>
    {
        let mut builder = Ipv4Builder::new(self.src, self.dst, self.mtu, payload);
        self.tx.send(&mut builder)
    }
}


pub struct Ipv4Builder<'p, P: Payload<Ipv4Fields> + 'p> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    mtu: usize,
    offset: usize,
    payload: &'p mut P,
}

impl<'p, P: Payload<Ipv4Fields>> Ipv4Builder<'p, P> {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, mtu: usize, payload: &'p mut P) -> Self {
        assert!(mtu >= Ipv4Packet::minimum_packet_size());
        Ipv4Builder {
            src: src,
            dst: dst,
            mtu: mtu,
            offset: 0,
            payload: payload,
        }
    }

    fn max_payload_per_fragment(&self) -> usize {
        (self.mtu - Ipv4Packet::minimum_packet_size()) & !0b111
    }

    fn ip_packets_per_payload_packet(&self) -> usize {
        let max_payload_per_fragment = self.max_payload_per_fragment();
        (cmp::max(1, self.payload.packet_size()) + max_payload_per_fragment - 1) /
        max_payload_per_fragment
    }

    fn evenly_distributed_payload_per_fragment(&self) -> usize {
        let ip_packets_per_payload_packet = self.ip_packets_per_payload_packet();
        (self.payload.packet_size() + ip_packets_per_payload_packet - 1) /
        ip_packets_per_payload_packet
    }
}

impl<'p, P: Payload<Ipv4Fields>> Payload<EthernetFields> for Ipv4Builder<'p, P> {
    fn fields(&self) -> &EthernetFields {
        static FIELDS: EthernetFields = EthernetFields(EtherTypes::Ipv4);
        &FIELDS
    }

    fn num_packets(&self) -> usize {
        self.ip_packets_per_payload_packet() * self.payload.num_packets()
    }

    fn packet_size(&self) -> usize {
        Ipv4Packet::minimum_packet_size() + self.evenly_distributed_payload_per_fragment()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIpv4Packet::new(buffer).expect("Too small buffer given");
        pkg.set_version(4);
        pkg.set_dscp(0); // https://en.wikipedia.org/wiki/Differentiated_services
        pkg.set_ecn(0); // https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        pkg.set_ttl(40);
        // ip_pkg.set_options(vec![]); // We currently don't support options
        pkg.set_header_length(5); // 5 is for no option fields
        pkg.set_identification(0);
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_fragment_offset((self.offset / 8) as u16);

        // let bytes_remaining = self.payload_len - self.offset;
        // let bytes_max = pkg.payload().len();
        // let payload_size = if bytes_remaining <= bytes_max {
        //     pkg.set_flags(NO_FLAGS);
        //     bytes_remaining
        // } else {
        //     pkg.set_flags(MORE_FRAGMENTS);
        //     bytes_max & !0b111 // Round down to divisable by 8
        // };
        // let total_length = payload_size + Ipv4Packet::minimum_packet_size();
        // pkg.set_total_length(total_length as u16);

        pkg.set_next_level_protocol(self.payload.fields().0);
        // self.payload.build(&mut pkg.payload_mut()[..payload_size]);

        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);

        // self.offset += payload_size;
    }
}


#[cfg(test)]
mod tests {
    use {TxResult, TxError, CustomPayload};
    use ethernet::EthernetTx;

    use pnet::packet::Packet;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::util::MacAddr;

    use std::error::Error;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    use super::*;
    use super::super::MORE_FRAGMENTS;
    use testing::MockTx;

    lazy_static! {
        static ref SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
        static ref DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
        static ref FIELDS: Ipv4Fields = Ipv4Fields(IpNextHeaderProtocols::Tcp);
        static ref EMPTY_PAYLOAD: CustomPayload<'static, Ipv4Fields> = CustomPayload::new(*FIELDS, &[]);
    }

    #[test]
    fn max_payload_per_fragment_7() {
        let mut payload = EMPTY_PAYLOAD.clone();
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 27, &mut payload);
        assert_eq!(0, testee.max_payload_per_fragment());
    }

    #[test]
    fn max_payload_per_fragment_8() {
        let mut payload = EMPTY_PAYLOAD.clone();
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(8, testee.max_payload_per_fragment());
    }

    #[test]
    fn max_payload_per_fragment_9() {
        let mut payload = EMPTY_PAYLOAD.clone();
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 29, &mut payload);
        assert_eq!(8, testee.max_payload_per_fragment());
    }

    #[test]
    fn max_payload_per_fragment_16() {
        let mut payload = EMPTY_PAYLOAD.clone();
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 36, &mut payload);
        assert_eq!(16, testee.max_payload_per_fragment());
    }

    #[test]
    fn max_payload_per_fragment_1500() {
        let mut payload = EMPTY_PAYLOAD.clone();
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 1500, &mut payload);
        assert_eq!(1480, testee.max_payload_per_fragment());
    }

    #[test]
    fn ip_packets_per_payload_packet_fragmented() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 16, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 29, &mut payload);
        assert_eq!(2, testee.ip_packets_per_payload_packet());
    }

    #[test]
    fn ip_packets_per_payload_packet_fragmented_2() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 9, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(2, testee.ip_packets_per_payload_packet());
    }

    #[test]
    fn ip_packets_per_payload_packet_fits() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 8, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(1, testee.ip_packets_per_payload_packet());
    }

    #[test]
    fn ip_packets_per_payload_packet_fits_2() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 10, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 1500, &mut payload);
        assert_eq!(1, testee.ip_packets_per_payload_packet());
    }

    #[test]
    fn evenly_distributed_payload_per_fragment() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 1480, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 1500, &mut payload);
        assert_eq!(1480, testee.evenly_distributed_payload_per_fragment());
    }

    #[test]
    fn evenly_distributed_payload_per_fragment_fragmented() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 1481, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 1500, &mut payload);
        assert_eq!(741, testee.evenly_distributed_payload_per_fragment());
    }

    #[test]
    fn evenly_distributed_payload_per_fragment_many_fragments() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 63, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(8, testee.evenly_distributed_payload_per_fragment());
    }

    #[test]
    fn evenly_distributed_payload_per_fragment_many_fragments_2() {
        let mut payload = CustomPayload::with_packet_size(*FIELDS, 64, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(8, testee.evenly_distributed_payload_per_fragment());
    }

    #[test]
    fn num_packets_fits() {
        let mut payload = CustomPayload::exact(*FIELDS, 3, 2, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(3, testee.num_packets());
    }

    #[test]
    fn num_packets_fits_2() {
        let mut payload = CustomPayload::exact(*FIELDS, 3, 8, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(3, testee.num_packets());
    }

    #[test]
    fn num_packets_fragmented() {
        let mut payload = CustomPayload::exact(*FIELDS, 3, 10, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(6, testee.num_packets());
    }

    #[test]
    fn packet_size_fits() {
        let mut payload = CustomPayload::exact(*FIELDS, 3, 180, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 1500, &mut payload);
        assert_eq!(20 + 180, testee.packet_size());
    }

    #[test]
    fn packet_size_fragmented() {
        let mut payload = CustomPayload::exact(*FIELDS, 3, 10, &[]);
        let testee = Ipv4Builder::new(*SRC_IP, *DST_IP, 28, &mut payload);
        assert_eq!(20 + 5, testee.packet_size());
    }

    #[test]
    #[should_panic]
    fn mtu_smaller_than_header() {
        let (tx, _) = MockTx::new();
        let _testee = Ipv4Tx::new(tx, *SRC_IP, *DST_IP, 19);
    }

    #[test]
    fn tx_fragmented() {
        let (tx, rx) = MockTx::new();
        let mut testee = Ipv4Tx::new(tx, *SRC_IP, *DST_IP, 20 + 8);

        let data = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut payload = CustomPayload::new(Ipv4Fields(IpNextHeaderProtocols::Tcp), data);
        testee.send(&mut payload).unwrap();

        let pkg1 = rx.try_recv().unwrap();
        let pkg2 = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());

        let id1 = check_pkg(&pkg1, *SRC_IP, *DST_IP, true, 0, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let id2 = check_pkg(&pkg2, *SRC_IP, *DST_IP, false, 8, &[8, 9]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_not_fragmented() {
        let (tx, rx) = MockTx::new();
        let mut ipv4_tx = Ipv4Tx::new(tx, *SRC_IP, *DST_IP, 1500);

        let payload_data = (0..100).collect::<Vec<u8>>();
        let mut payload = CustomPayload::new(Ipv4Fields(IpNextHeaderProtocols::Tcp), &payload_data);
        ipv4_tx.send(&mut payload).unwrap();

        let pkg = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());

        check_pkg(&pkg, *SRC_IP, *DST_IP, false, 0, &payload_data);
    }

    fn check_pkg(pkg_buffer: &[u8],
                 src: Ipv4Addr,
                 dst: Ipv4Addr,
                 is_fragment: bool,
                 offset: u16,
                 payload: &[u8])
                 -> u16 {
        let pkg = Ipv4Packet::new(pkg_buffer).unwrap();
        assert_eq!(src, pkg.get_source());
        assert_eq!(dst, pkg.get_destination());;
        assert_eq!(is_fragment, pkg.get_flags() == MORE_FRAGMENTS);
        assert_eq!(offset, pkg.get_fragment_offset() * 8);
        assert_eq!(payload.len() + Ipv4Packet::minimum_packet_size(),
                   pkg.get_total_length() as usize);
        assert_eq!(payload, &pkg.payload()[0..payload.len()]);
        pkg.get_identification()
    }
}
