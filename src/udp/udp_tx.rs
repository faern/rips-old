use {Tx, Payload, TxResult};
use ipv4::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use ipv4::Ipv4Fields;

use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum_adv};

use std::cmp;
use std::net::SocketAddrV4;

// pub struct UdpFields<'a>(pub &'a [u8]);


// #[derive(Clone)]
// pub struct UdpTx<T> {
//     tx: T,
//     src: SocketAddrV4,
//     dst: SocketAddrV4,
// }

// impl<T> UdpTx<T> {
//     pub fn new(tx: T, src: SocketAddrV4, dst: SocketAddrV4) -> Self {
//         UdpTx {
//             tx: tx,
//             src: src,
//             dst: dst,
//         }
//     }

//     pub fn send(&mut self, data: &[u8]) -> Option<TxResult<()>> {}
// }

// impl<'a, T: Tx<Ipv4Fields>> Tx<UdpFields<'a>> for UdpTx<T> {
//     fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
//         where P: Payload<UdpFields<'a>>
//     {
//         let mut builder = UdpBuilder::new(self.src, self.dst, payload);
//         self.tx.send(&mut builder)
//     }
// }


pub struct UdpBuilder<'a> {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    header_sent: bool,
    offset: usize,
    payload: &'a [u8],
}

impl<'a> UdpBuilder<'a> {
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4, payload: &'a [u8]) -> Self {
        UdpBuilder {
            src: src,
            dst: dst,
            header_sent: false,
            offset: 0,
            payload: payload,
        }
    }
}

impl<'a> Payload<Ipv4Fields> for UdpBuilder<'a> {
    fn fields(&self) -> &Ipv4Fields {
        static FIELDS: Ipv4Fields = Ipv4Fields(IpNextHeaderProtocols::Udp);
        &FIELDS
    }

    fn num_packets(&self) -> usize {
        1
    }

    fn packet_size(&self) -> usize {
        UdpPacket::minimum_packet_size() + self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let payload_buffer = if !self.header_sent {
            self.header_sent = true;
            {
                let header_buffer = &mut buffer[..UdpPacket::minimum_packet_size()];
                let mut pkg = MutableUdpPacket::new(header_buffer).unwrap();
                pkg.set_source(self.src.port());
                pkg.set_destination(self.dst.port());
                pkg.set_length(self.packet_size() as u16);
                let checksum = ipv4_checksum_adv(&pkg.to_immutable(),
                                                 self.payload,
                                                 *self.src.ip(),
                                                 *self.dst.ip());
                pkg.set_checksum(checksum);
            }
            &mut buffer[UdpPacket::minimum_packet_size()..]
        } else {
            buffer
        };
        let start = self.offset;
        let len = cmp::min(payload_buffer.len(), self.payload.len() - start);
        let end = start + len;
        payload_buffer[..len].copy_from_slice(&self.payload[start..end]);
        self.offset = end;
    }
}

#[cfg(test)]
mod tests {
    use Payload;
    use pnet::packet::Packet;
    use pnet::packet::udp::UdpPacket;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use super::*;

    lazy_static! {
        static ref ADDR1: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 99, 250, 15), 8080);
        static ref ADDR2: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 105), 22);
    }

    #[test]
    #[should_panic]
    fn udp_builder_too_short() {
        let mut buffer = vec![0; 7];
        let mut builder = UdpBuilder::new(*ADDR1, *ADDR2, &[]);
        builder.build(&mut buffer);
    }

    #[test]
    fn udp_builder_header() {
        let data = &mut [3, 2];
        let mut builder = UdpBuilder::new(*ADDR1, *ADDR2, data);

        let mut buffer = vec![0; 1000];
        builder.build(&mut buffer);

        let pkg = UdpPacket::new(&buffer).unwrap();
        assert_eq!(ADDR1.port(), pkg.get_source());
        assert_eq!(ADDR2.port(), pkg.get_destination());
        assert_eq!(10, pkg.get_length());
        assert_eq!(5806, pkg.get_checksum());
        assert_eq!([3, 2, 0], pkg.payload()[0..3]);
    }

    #[test]
    fn udp_builder_two_build_calls() {
        let mut buffer = vec![0; 8];
        let data = &[11, 12, 13, 14, 15, 16, 17, 18, 19];
        let mut builder = UdpBuilder::new(*ADDR1, *ADDR2, data);
        // Build header, but we don't test that here
        builder.build(&mut buffer);

        // Build first 8 bytes of payload
        builder.build(&mut buffer);
        assert_eq!([11, 12, 13, 14, 15, 16, 17, 18], buffer[..]);

        // Build last payload byte
        builder.build(&mut buffer);
        assert_eq!([19], buffer[..1]);
    }
}
