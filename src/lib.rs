use std::{collections::HashMap, marker::PhantomData};

use num_enum::FromPrimitive;
use once_cell::sync::Lazy;

#[derive(Debug,Clone,Copy)]
pub struct Sack {
    left_edge: u32,
    right_edge: u32,
}

#[derive(Debug,Clone,Copy)]
pub struct Timestamp {
    value: u32,
    echo_reply: u32,
}

#[derive(Debug,FromPrimitive,Clone,Copy)]
#[repr(u8)]
pub enum TcpOption {
    EndOfOptionList = 0,
    NoOperation = 1,
    MaximumSegmentSize(u16) = 2,
    WindowScale(u8) = 3,
    SackPermitted = 4,
    Sack(Vec<Sack>) = 5,
    Timestamp(Timestamp) = 8,
    Skeeter = 16,
    Bubba = 17,
    TrailerChecksum(u8) = 18,
    SCPSCapabilities = 20,
    SelectiveNegativeAcknowledgements = 21,
    RecordBoundaries = 22,
    CorruptionExperienced = 23,
    SNAP = 24,
    TCPCompressionFilter = 26,
    QuickStartResponse(u64) = 27,
    UserTimeout(u16) = 28,
    TCPAuthenticationOption = 29,
    MultipathTCP(Vec<u8>) = 30, // TODO: Deserialize this better
    TCPFastOpenCookie(u128) = 34,
    EncryptionNegotiation(Vec<u8>) = 69, // TODO: Deserialize this better
    AccECNOrder0(Vec<u8>) = 172,         // Newly registered, needs deserialization
    AccECNOrder1(Vec<u8>) = 174,         // Newly registered, needs deserialization
    RFC3692Experiment1(Vec<u8>) = 253,   // Experimental, needs deserialization
    RFC3692Experiment2(Vec<u8>) = 254,   // Experimental, needs deserialization
}

type OptionParser = Box<dyn Fn(&[u8]) -> Option<TcpOption> + Send + Sync>;




// Define the static map with closures wrapped in a Box for dynamic dispatch.
static OPTION_PARSERS: Lazy<HashMap<u8, OptionParser>> = Lazy::new(|| {
    let mut parsers: HashMap<u8, OptionParser> = HashMap::new();

    // NoOperation parser
    parsers.insert(1, Box::new(|_: &[u8]| Some(TcpOption::NoOperation)));

    // MaximumSegmentSize parser
    parsers.insert(
        2,
        Box::new(|data: &[u8]| {
            if data.len() != 4 {
                return None;
            }
            let mss = {
                let mut mss_bytes = [0u8; 2];
                mss_bytes.copy_from_slice(&data[2..data.len() as usize]);
                u16::from_be_bytes(mss_bytes)
            };
            Some(TcpOption::MaximumSegmentSize(mss))
        }),
    );

    // WindowScale parser
    parsers.insert(
        3,
        Box::new(|data: &[u8]| {
            if data.len() != 3 {
                return None;
            }
            let ws = data[2];
            Some(TcpOption::WindowScale(ws))
        }),
    );

    // SackPermitted parser
    parsers.insert(4, Box::new(|_: &[u8]| Some(TcpOption::SackPermitted)));

    // Sack parser
    parsers.insert(
        5,
        Box::new(|data: &[u8]| {
            if data.len() < 2 || data.len() % 8 != 2 { // Must be at least 2 bytes and x-2 % 8 == 0
                return None;
            }
            let mut sacks = Vec::new();
            for i in (2..data.len()).step_by(8) {
                if i + 8 > data.len() {
                    break; // Exit if we cannot fill the right edge
                }
                let left_edge = {
                    let mut left_edge_bytes = [0u8; 4];
                    left_edge_bytes.copy_from_slice(&data[i..i + 4]);
                    u32::from_be_bytes(left_edge_bytes)
                };
                let right_edge = {
                    let mut right_edge_bytes = [0u8; 4];
                    right_edge_bytes.copy_from_slice(&data[i + 4..i + 8]);
                    u32::from_be_bytes(right_edge_bytes)
                };
                sacks.push(Sack { left_edge, right_edge });
            }
            Some(TcpOption::Sack(sacks))
        }),
    );

    // Timestamp parser
    parsers.insert(
        8,
        Box::new(|data: &[u8]| {
            if data.len() != 10 {
                return None;
            }
            let tsval = {
                let mut tsval_bytes = [0u8; 4];
                tsval_bytes.copy_from_slice(&data[2..6]);
                u32::from_be_bytes(tsval_bytes)
            };
            let tsecr = {
                let mut tsecr_bytes = [0u8; 4];
                tsecr_bytes.copy_from_slice(&data[6..10]);
                u32::from_be_bytes(tsecr_bytes)
            };
            Some(TcpOption::Timestamp(Timestamp { value: tsval, echo_reply: tsecr }))
        }),
    );

    // Skeeter parser
    parsers.insert(16, Box::new(|_: &[u8]| Some(TcpOption::Skeeter)));

    // Bubba parser
    parsers.insert(17, Box::new(|_: &[u8]| Some(TcpOption::Bubba)));

    // TrailerChecksum parser
    parsers.insert(
        18,
        Box::new(|data: &[u8]| {
            if data.len() != 3 {
                return None;
            }
            let checksum = data[2];
            Some(TcpOption::TrailerChecksum(checksum))
        }),
    );

    // SCPSCapabilities parser
    parsers.insert(20, Box::new(|_: &[u8]| Some(TcpOption::SCPSCapabilities)));

    // SelectiveNegativeAcknowledgements parser
    parsers.insert(21, Box::new(|_: &[u8]| Some(TcpOption::SelectiveNegativeAcknowledgements)));

    // RecordBoundaries parser
    parsers.insert(22, Box::new(|_: &[u8]| Some(TcpOption::RecordBoundaries)));

    // CorruptionExperienced parser
    parsers.insert(23, Box::new(|_: &[u8]| Some(TcpOption::CorruptionExperienced)));

    // SNAP parser
    parsers.insert(24, Box::new(|_: &[u8]| Some(TcpOption::SNAP)));

    // TCPCompressionFilter parser
    parsers.insert(26, Box::new(|_: &[u8]| Some(TcpOption::TCPCompressionFilter)));

    // QuickStartResponse parser
    parsers.insert(
        27,
        Box::new(|data: &[u8]| {
            if data.len() != 8 {
                return None;
            }
            let cookie = {
                let mut cookie_bytes = [0u8; 8];
                cookie_bytes.copy_from_slice(&data[2..8]);
                u64::from_be_bytes(cookie_bytes)
            };
            Some(TcpOption::QuickStartResponse(cookie))
        }),
    );

    // UserTimeout parser
    parsers.insert(
        28,
        Box::new(|data: &[u8]| {
            if data.len() != 4 {
                return None;
            }
            let timeout = {
                let mut timeout_bytes = [0u8; 2];
                timeout_bytes.copy_from_slice(&data[2..4]);
                u16::from_be_bytes(timeout_bytes)
            };
            Some(TcpOption::UserTimeout(timeout))
        }),
    );

    // TCPAuthenticationOption parser
    parsers.insert(29, Box::new(|_: &[u8]| Some(TcpOption::TCPAuthenticationOption)));

    // MultipathTCP parser
    parsers.insert(
        30,
        Box::new(|data: &[u8]| {
            if data.len() < 4 {
                return None;
            }
            let mut data_bytes = Vec::new();
            data_bytes.extend_from_slice(&data[2..data.len()]);
            Some(TcpOption::MultipathTCP(data_bytes))
        }),
    );

    // TCPFastOpenCookie parser
    parsers.insert(
        34,
        Box::new(|data: &[u8]| {
            if data.len() != 18 {
                return None;
            }
            let cookie = {
                let mut cookie_bytes = [0u8; 16];
                cookie_bytes.copy_from_slice(&data[2..18]);
                u128::from_be_bytes(cookie_bytes)
            };
            Some(TcpOption::TCPFastOpenCookie(cookie))
        }),
    );

    // EncryptionNegotiation parser
    parsers.insert(
        69,
        Box::new(|data: &[u8]| {
            if data.len() < 4 {
                return None;
            }
            let mut data_bytes = Vec::new();
            data_bytes.extend_from_slice(&data[2..data.len()]);
            Some(TcpOption::EncryptionNegotiation(data_bytes))
        }),
    );

    // AccECNOrder0 parser
    parsers.insert(
        172,
        Box::new(|data: &[u8]| {
            if data.len() < 4 {
                return None;
            }
            let mut data_bytes = Vec::new();
            data_bytes.extend_from_slice(&data[2..data.len()]);
            Some(TcpOption::AccECNOrder0(data_bytes))
        }),
    );

    // AccECNOrder1 parser
    parsers.insert(
        174,
        Box::new(|data: &[u8]| {
            if data.len() < 4 {
                return None;
            }
            let mut data_bytes = Vec::new();
            data_bytes.extend_from_slice(&data[2..data.len()]);
            Some(TcpOption::AccECNOrder1(data_bytes))
        }),
    );




    parsers
});
