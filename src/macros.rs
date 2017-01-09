#[macro_export]
/// Macro for sending on a Tx until it does not return an `TxError::InvalidTx`.
macro_rules! tx_send {
    ($create:expr; $($arg:expr),*) => {{
        let mut result = None;
        while result.is_none() {
            let mut tx = $create();
            result = tx.send($($arg),*);
        }
        result.unwrap()
    }};
}
