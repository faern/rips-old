use std::cmp;

pub trait TxPayload<P> {
    fn send<Payload: P>(&mut self, payload: Payload) -> Payload;
}

/// Super trait to any payload. Represents any type that can become the payload
/// of a packet.
pub trait Payload {
    fn num_packets(&self) -> usize;

    fn packet_size(&self) -> usize;

    /// Returns how many bytes this payload will occupy in total.
    /// Returns the same length on every call, does not vary as it is being
    /// consumed by calls to the `build` method.
    // fn len(&self) -> usize;
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
pub struct BasicPayload<'a> {
    offset: usize,
    payload: &'a [u8],
}

impl<'a> BasicPayload<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        BasicPayload {
            offset: 0,
            payload: payload,
        }
    }
}

impl<'a> Payload for BasicPayload<'a> {
    fn num_packets(&self) -> usize {
        if self.payload.is_empty() { 0 } else { 1 }
    }

    fn packet_size(&self) -> usize {
        self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let start = self.offset;
        let end = cmp::min(start + buffer.len(), self.payload.len());
        self.offset = end;
        buffer[0..end - start].copy_from_slice(&self.payload[start..end]);
    }
}

pub trait HasPayload {
    fn get_payload(&self) -> &Payload;
    fn get_payload_mut(&mut self) -> &mut Payload;
}

impl<T> Payload for T
    where T: HasPayload
{
    fn num_packets(&self) -> usize {
        self.get_payload().num_packets()
    }

    fn packet_size(&self) -> usize {
        self.get_payload().packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        self.get_payload_mut().build(buffer)
    }
}

#[cfg(test)]
mod basic_payload_tests {
    use Payload;
    use super::*;

    #[test]
    fn len_zero() {
        let testee = BasicPayload::new(&[]);
        assert_eq!(0, testee.num_packets());
        assert_eq!(0, testee.packet_size());
    }

    #[test]
    fn len_three() {
        let data = &[5, 6, 7];
        let testee = BasicPayload::new(data);
        assert_eq!(1, testee.num_packets());
        assert_eq!(3, testee.packet_size());
    }

    #[test]
    fn build_without_data() {
        let mut testee = BasicPayload::new(&[]);
        let mut buffer = vec![99; 1];
        testee.build(&mut buffer);
        assert_eq!(99, buffer[0]);
    }

    #[test]
    fn build_with_data() {
        let data = &[5, 6, 7];
        let mut testee = BasicPayload::new(data);
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
        let mut testee = BasicPayload::new(data);
        let mut buffer = vec![0; 3];
        testee.build(&mut buffer);
        assert_eq!(&[5, 6, 0], &buffer[..]);
    }
}
