use std::error::Error;
use std::fmt;
use std::io;

/// Enum representing errors happening while trying to send packets to the
/// network
#[derive(Debug)]
pub enum TxError {
    /// Returned when the payload does not fit in the given protocol. For
    /// example sending a
    /// packet with more than 2^16 bytes in a protocol with a 16 bit length
    /// field
    TooLargePayload,

    /// Returned when there was an `IoError` during transmission
    IoError(io::Error),

    /// Any other error not covered by the more specific enum variants
    Other(String),
}

impl From<io::Error> for TxError {
    fn from(e: io::Error) -> Self {
        TxError::IoError(e)
    }
}

impl From<TxError> for io::Error {
    fn from(e: TxError) -> Self {
        let other = |msg| io::Error::new(io::ErrorKind::Other, msg);
        match e {
            TxError::TooLargePayload => other("Too large payload".to_owned()),
            TxError::IoError(e2) => e2,
            TxError::Other(msg) => other(format!("Other: {}", msg)),
        }
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use TxError::*;
        fmt.write_str(self.description())?;
        match *self {
            IoError(ref e) => fmt.write_str(&format!(": {}", e)),
            Other(ref s) => fmt.write_str(&format!(": {}", s)),
            _ => Ok(()),
        }
    }
}

impl Error for TxError {
    fn description(&self) -> &str {
        use TxError::*;
        match *self {
            TooLargePayload => "Too large payload",
            IoError(..) => "IO error",
            Other(..) => "Other error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        if let TxError::IoError(ref e) = *self {
            Some(e)
        } else {
            None
        }
    }
}

/// Error returned by the `recv` method of `*Rx` objects when there is
/// something wrong with the
/// incoming packet.
#[derive(Debug, Eq, PartialEq)]
pub enum RxError {
    /// When nothing is listening for this packet, so it becomes silently
    /// discarded.
    NoListener(String),

    /// When a packet contains an invalid checksum.
    InvalidChecksum,

    /// When the length of the packet does not match the
    /// requirements or header content of a protocol
    InvalidLength,

    /// When other packet content is invalid.
    InvalidContent,

    /// Some error that was not covered by the more specific errors in this
    /// enum.
    Other(String),
}

impl fmt::Display for RxError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use RxError::*;
        fmt.write_str(self.description())?;
        match *self {
            NoListener(ref s) => fmt.write_str(&format!(": {}", s)),
            Other(ref s) => fmt.write_str(&format!(": {}", s)),
            _ => Ok(()),
        }
    }
}

impl Error for RxError {
    fn description(&self) -> &str {
        use RxError::*;
        match *self {
            NoListener(..) => "No listener for packet",
            InvalidChecksum => "Invalid checksum in packet",
            InvalidLength => "Invalid length field in packet",
            InvalidContent => "Invalid content in packet",
            Other(..) => "Other error",
        }
    }

    // fn cause(&self) -> Option<&Error> {}
}


/// Error returned upon invalid usage or state of the stack.
#[derive(Debug)]
pub enum StackError {
    IllegalArgument,
    NoRouteToHost,
    InvalidInterface,
    TxError(TxError),
    IoError(io::Error),
}

impl From<TxError> for StackError {
    fn from(e: TxError) -> StackError {
        StackError::TxError(e)
    }
}

impl From<io::Error> for StackError {
    fn from(e: io::Error) -> StackError {
        StackError::IoError(e)
    }
}

impl From<StackError> for io::Error {
    fn from(e: StackError) -> io::Error {
        let other = |msg| io::Error::new(io::ErrorKind::Other, msg);
        match e {
            StackError::IllegalArgument => other("Illegal argument".to_owned()),
            StackError::NoRouteToHost => other("No route to host".to_owned()),
            StackError::InvalidInterface => other("Invalid interface".to_owned()),
            StackError::IoError(io_e) => io_e,
            StackError::TxError(txe) => txe.into(),
        }
    }
}

impl fmt::Display for StackError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use StackError::*;
        fmt.write_str(self.description())?;
        match *self {
            TxError(ref e) => fmt.write_str(&format!(": {}", e)),
            IoError(ref e) => fmt.write_str(&format!(": {}", e)),
            _ => Ok(()),
        }
    }
}

impl Error for StackError {
    fn description(&self) -> &str {
        use StackError::*;
        match *self {
            IllegalArgument => "Illegal argument",
            NoRouteToHost => "No route to host",
            InvalidInterface => "Invalid interface",
            TxError(..) => "Transmission error",
            IoError(..) => "IO error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        use StackError::*;
        match *self {
            TxError(ref e) => Some(e),
            IoError(ref e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConversionError {
    NoMacAddress,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Error for ConversionError {
    fn description(&self) -> &str {
        use ConversionError::*;
        match *self {
            NoMacAddress => "No MAC address on interface",
        }
    }
}
