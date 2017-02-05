use {Tx, Payload, TxResult};

use std::sync::mpsc::{self, Receiver, Sender};

#[derive(Clone)]
pub struct MockTx {
    chan: Sender<Box<[u8]>>,
}

impl MockTx {
    pub fn new() -> (Self, Receiver<Box<[u8]>>) {
        let (tx, rx) = mpsc::channel();
        (MockTx { chan: tx }, rx)
    }
}

impl<T> Tx<T> for MockTx {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<T>
    {
        for _ in 0..payload.num_packets() {
            let mut buffer = vec![0; payload.packet_size()];
            payload.build(&mut buffer);
            let buffer = buffer.into_boxed_slice();
            let _ = self.chan.send(buffer);
        }
        Some(Ok(()))
    }
}
