use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Eq)]
pub enum TypedData {
    Null,
    Bool(bool),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    String(String),
    Binary(Vec<u8>),
}

impl TypedData {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let type_id = bytes[0] >> 4; // First 4 bits are TYPE
        let flags = bytes[0] & 0x0F; // Last 4 bits are FLAGS

        match type_id {
            0 => Some(Self::Null),
            1 => Some(Self::Bool(flags & 1 != 0)), // Bool is stored in FLAGS
            2 => bytes
                .get(1..5)
                .and_then(|b| Some(Self::Int32(i32::from_be_bytes(b.try_into().ok()?)))),
            3 => bytes
                .get(1..5)
                .and_then(|b| Some(Self::UInt32(u32::from_be_bytes(b.try_into().ok()?)))),
            4 => bytes
                .get(1..9)
                .and_then(|b| Some(Self::Int64(i64::from_be_bytes(b.try_into().ok()?)))),
            5 => bytes
                .get(1..9)
                .and_then(|b| Some(Self::UInt64(u64::from_be_bytes(b.try_into().ok()?)))),
            6 => bytes
                .get(1..5)
                .map(|b| Self::IPv4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            7 => bytes
                .get(1..17)
                .and_then(|b| Some(Self::IPv6(Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?)))),
            8 | 9 => {
                let length = bytes.get(1).cloned()? as usize;
                let data = bytes.get(2..2 + length)?;
                Some(if type_id == 8 {
                    Self::String(String::from_utf8_lossy(data).into_owned())
                } else {
                    Self::Binary(data.to_vec())
                })
            }
            _ => None,
        }
    }
}
