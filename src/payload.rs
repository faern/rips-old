use std::cmp;

/// Super trait to any payload. Represents any type that can become the payload
/// of a packet.
pub trait Payload<ParentFields> {
    fn fields(&self) -> &ParentFields;

    fn num_packets(&self) -> usize;

    fn packet_size(&self) -> usize;

    /// Construct some bytes of this `Payload` into the given `buffer`. If
    /// `buffer` is smaller than the remaining length of this `Payload` it will
    /// fill `buffer` and keep the remaining data for subsequent calls to
    /// `build`.
    ///
    /// The `Payload` will construct exactly as many bytes as `len()` returns.
    ///
    /// Can be called an unlimited number of times. After the entire `Payload`
    /// has been built subsequent calls will not modify `buffer`.
    ///
    /// # Panics
    ///
    /// May panic if the given buffer is too small for the header of the
    /// payload. Every implementer must support multiple calls to this method
    /// and be able to incrementaly build itself into buffers, but they are
    /// allowed to panic if their headers don't fit into the `buffer` of the
    /// first call. No, you can't figure out the header size of a `Payload`,
    /// this is something for the future.
    fn build(&mut self, buffer: &mut [u8]);
}

#[derive(Clone)]
pub struct CustomPayload<'a, ParentFields> {
    parent_fields: ParentFields,
    num_packets: usize,
    packet_size: usize,
    offset: usize,
    payload: &'a [u8],
}

impl<'a, ParentFields> CustomPayload<'a, ParentFields> {
    pub fn new(parent_fields: ParentFields, payload: &'a [u8]) -> Self {
        Self::with_packet_size(parent_fields, payload.len(), payload)
    }

    pub fn with_packet_size(parent_fields: ParentFields,
                            packet_size: usize,
                            payload: &'a [u8])
                            -> Self {
        CustomPayload {
            parent_fields: parent_fields,
            num_packets: Self::calculate_num_packets(payload.len(), packet_size),
            packet_size: packet_size,
            offset: 0,
            payload: payload,
        }
    }

    pub fn exact(parent_fields: ParentFields,
                 num_packets: usize,
                 packet_size: usize,
                 payload: &'a [u8])
                 -> Self {
        CustomPayload {
            parent_fields: parent_fields,
            num_packets: num_packets,
            packet_size: packet_size,
            offset: 0,
            payload: payload,
        }
    }

    fn calculate_num_packets(payload_len: usize, packet_size: usize) -> usize {
        if payload_len == 0 || packet_size == 0 {
            1
        } else {
            (payload_len + packet_size - 1) / packet_size
        }
    }
}

impl<'a, ParentFields> Payload<ParentFields> for CustomPayload<'a, ParentFields> {
    fn fields(&self) -> &ParentFields {
        &self.parent_fields
    }

    fn num_packets(&self) -> usize {
        self.num_packets
    }

    fn packet_size(&self) -> usize {
        self.packet_size
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let start = self.offset;
        let end = cmp::min(start + buffer.len(), self.payload.len());
        self.offset = end;
        buffer[0..end - start].copy_from_slice(&self.payload[start..end]);
    }
}


#[cfg(test)]
mod custom_payload_tests {
    use super::*;

    #[test]
    fn no_data() {
        let testee = CustomPayload::new((), &[]);
        assert_eq!(1, testee.num_packets());
        assert_eq!(0, testee.packet_size());
    }

    #[test]
    fn len_three() {
        let data = &[5, 6, 7];
        let testee = CustomPayload::new((), data);
        assert_eq!(1, testee.num_packets());
        assert_eq!(3, testee.packet_size());
    }

    #[test]
    fn build_without_data() {
        let mut testee = CustomPayload::new((), &[]);
        let mut buffer = vec![99; 1];
        testee.build(&mut buffer);
        assert_eq!(99, buffer[0]);
    }

    #[test]
    fn build_with_data() {
        let data = &[5, 6, 7];
        let mut testee = CustomPayload::new((), data);
        let mut buffer = vec![0; 1];
        testee.build(&mut buffer[0..0]);

        testee.build(&mut buffer);
        assert_eq!(5, buffer[0]);
        testee.build(&mut buffer);
        assert_eq!(6, buffer[0]);
        testee.build(&mut buffer);
        assert_eq!(7, buffer[0]);

        testee.build(&mut buffer[0..0]);
    }

    #[test]
    fn build_with_larger_buffer() {
        let data = &[5, 6];
        let mut testee = CustomPayload::new((), data);
        let mut buffer = vec![0; 3];
        testee.build(&mut buffer);
        assert_eq!(&[5, 6, 0], &buffer[..]);
    }

    #[test]
    fn fields() {
        use ethernet::{EthernetFields, EtherTypes};

        let testee = CustomPayload::new(EthernetFields(EtherTypes::Ipv6), &[]);
        assert_eq!(EtherTypes::Ipv6, testee.fields().0);

        let testee = CustomPayload::new(EthernetFields(EtherTypes::Arp), &[]);
        assert_eq!(EtherTypes::Arp, testee.fields().0);

        let testee = CustomPayload::new((), &[]);
        assert_eq!((), *testee.fields());
    }
}
