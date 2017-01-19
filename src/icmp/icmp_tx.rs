use {Tx, Payload, CustomPayload, TxResult};
use ipv4::Ipv4Fields;

use pnet::packet::MutablePacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket, checksum, IcmpTypes};
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::ip::IpNextHeaderProtocols;

pub struct IcmpFields {
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub build_header: Box<Fn(&mut MutableIcmpPacket)>,
}

impl IcmpFields {
    pub fn echo_request() -> Self {
        let build_header = Box::new(|pkg: &mut MutableIcmpPacket| {
            let mut echo_pkg = MutableEchoRequestPacket::new(pkg.packet_mut()).unwrap();
            echo_pkg.set_identifier(0);
            echo_pkg.set_sequence_number(0);
        });
        IcmpFields {
            icmp_type: IcmpTypes::EchoRequest,
            icmp_code: IcmpCodes::NoCode,
            build_header: build_header,
        }
    }
}

#[derive(Clone)]
pub struct IcmpTx<T> {
    tx: T,
}

impl<T: Tx<Ipv4Fields>> IcmpTx<T> {
    pub fn new(tx: T) -> Self {
        IcmpTx { tx: tx }
    }

    // Sends an Echo Request packet (ping) with the given payload.
    pub fn send_echo(&mut self, payload: &[u8]) -> Option<TxResult<()>> {
        let mut payload = CustomPayload::new(IcmpFields::echo_request(), payload);
        self.send(&mut payload)
    }
}

impl<T: Tx<Ipv4Fields>> Tx<IcmpFields> for IcmpTx<T> {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<IcmpFields>
    {
        let mut builder = IcmpBuilder::new(payload);
        self.tx.send(&mut builder)
    }
}


pub struct IcmpBuilder<'p, P: Payload<IcmpFields> + 'p> {
    payload: &'p mut P,
}

impl<'p, P: Payload<IcmpFields>> IcmpBuilder<'p, P> {
    pub fn new(payload: &'p mut P) -> Self {
        IcmpBuilder { payload: payload }
    }
}

impl<'p, P: Payload<IcmpFields>> Payload<Ipv4Fields> for IcmpBuilder<'p, P> {
    fn fields(&self) -> &Ipv4Fields {
        static FIELDS: Ipv4Fields = Ipv4Fields(IpNextHeaderProtocols::Icmp);
        &FIELDS
    }

    fn num_packets(&self) -> usize {
        self.payload.num_packets()
    }

    fn packet_size(&self) -> usize {
        8 + self.payload.packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIcmpPacket::new(buffer).unwrap();
        {
            let mut header_pkg = MutableIcmpPacket::new(&mut pkg.packet_mut()[..8]).unwrap();
            header_pkg.set_icmp_type(self.payload.fields().icmp_type);
            header_pkg.set_icmp_code(self.payload.fields().icmp_code);
            (self.payload.fields().build_header)(&mut header_pkg);
        }
        self.payload.build(&mut pkg.packet_mut()[8..]);
        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);
    }
}


#[cfg(test)]
mod tests {
    use {TxResult, TxError};
    use icmp::{IcmpTypes, EchoCodes};
    use ipv4::{Ipv4Tx, IpNextHeaderProtocol, IpNextHeaderProtocols};

    use pnet::packet::Packet;
    use pnet::packet::icmp::echo_request::EchoRequestPacket;

    use std::error::Error;
    use std::net::Ipv4Addr;
    use std::sync::mpsc::{self, Sender, Receiver};

    use super::*;
    use testing::MockTx;

    #[test]
    fn test_send_echo() {
        let (tx, read_handle) = MockTx::new();

        let mut testee = IcmpTx::new(tx);
        testee.send_echo(&[9, 55]).unwrap();

        let data = read_handle.try_recv().expect("Expected echo packet");
        let echo_pkg = EchoRequestPacket::new(&data).unwrap();
        assert_eq!(IcmpTypes::EchoRequest, echo_pkg.get_icmp_type());
        assert_eq!(EchoCodes::NoCode, echo_pkg.get_icmp_code());
        assert_eq!(61128, echo_pkg.get_checksum()); // For ident&seq == 0
        assert_eq!([9, 55], echo_pkg.payload());
    }
}
