use crate::varint::decode_varint;
use nom::{
    IResult,
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::be_u8,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L635>
///
/// ```text
/// Here is the bytewise representation of typed data:
///
///     TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
///
/// Supported types and their representation are:
///
///     TYPE                       |  ID | DESCRIPTION
///   -----------------------------+-----+----------------------------------
///      NULL                      |  0  |  NULL   : <0>
///      Boolean                   |  1  |  BOOL   : <1+FLAG>
///      32bits signed integer     |  2  |  INT32  : <2><VALUE:varint>
///      32bits unsigned integer   |  3  |  UINT32 : <3><VALUE:varint>
///      64bits signed integer     |  4  |  INT64  : <4><VALUE:varint>
///      32bits unsigned integer   |  5  |  UNIT64 : <5><VALUE:varint>
///      IPV4                      |  6  |  IPV4   : <6><STRUCT IN_ADDR:4 bytes>
///      IPV6                      |  7  |  IPV6   : <7><STRUCT IN_ADDR6:16 bytes>
///      String                    |  8  |  STRING : <8><LENGTH:varint><BYTES>
///      Binary                    |  9  |  BINARY : <9><LENGTH:varint><BYTES>
///     10 -> 15  unused/reserved  |  -  |  -
///   -----------------------------+-----+----------------------------------
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
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

/// Returns the Type ID and Flags from the first byte of the input
pub fn typed_data(input: &[u8]) -> IResult<&[u8], TypedData> {
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, type_and_flags) = be_u8(input)?;

    // TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
    //
    // First 4 bits are TYPE, last 4 bits are FLAGS
    let type_id = type_and_flags & 0x0F;
    let flags = type_and_flags >> 4;

    match type_id {
        0 => Ok((input, TypedData::Null)),
        1 => Ok((input, TypedData::Bool((flags & 1) != 0))),
        2 => decode_varint(input).map(|(i, v)| (i, TypedData::Int32(v as i32))),
        3 => decode_varint(input).map(|(i, v)| (i, TypedData::UInt32(v as u32))),
        4 => decode_varint(input).map(|(i, v)| (i, TypedData::Int64(v as i64))),
        5 => decode_varint(input).map(|(i, v)| (i, TypedData::UInt64(v))),
        6 => {
            if input.len() < 4 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(4usize)(input)?;
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok((input, TypedData::IPv4(addr)))
        }
        7 => {
            if input.len() < 16 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(16usize)(input)?;
            let addr = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
            Ok((input, TypedData::IPv6(addr)))
        }
        8 | 9 => {
            let (input, length) = decode_varint(input)?;

            if input.len() < length as usize {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }

            let (input, data) = take(length)(input)?;
            if type_id == 8 {
                let s = String::from_utf8_lossy(data).into_owned();
                Ok((input, TypedData::String(s)))
            } else {
                Ok((input, TypedData::Binary(data.to_vec())))
            }
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_loop_typed_data() {
        // Each test case is a tuple:
        // (description, input bytes, expected TypedData)
        let test_cases = vec![
            // Type 0: NULL
            ("NULL", vec![0x00], TypedData::Null),
            // Type 1: Boolean (false) - lower nibble is 1, flags=0 yields false.
            ("Bool false", vec![0x01], TypedData::Bool(false)),
            // Type 1: Boolean (true) - e.g. 0x11 gives type=1 and flags=1.
            ("Bool true", vec![0x11], TypedData::Bool(true)),
            // Type 2: 32-bit signed integer (INT32)
            // 0x02 followed by a varint-encoded value (here one-byte: 123)
            ("Int32", vec![0x02, 0x7B], TypedData::Int32(123)),
            // Type 3: 32-bit unsigned integer (UINT32)
            ("UInt32", vec![0x03, 0x7B], TypedData::UInt32(123)),
            // Type 4: 64-bit signed integer (INT64)
            ("Int64", vec![0x04, 0x2A], TypedData::Int64(42)),
            // Type 5: 64-bit unsigned integer (UINT64)
            ("UInt64", vec![0x05, 0x2A], TypedData::UInt64(42)),
            // Type 6: IPv4 address: 0x06 followed by 4 bytes.
            (
                "IPv4",
                vec![0x06, 192, 168, 0, 1],
                TypedData::IPv4(Ipv4Addr::new(192, 168, 0, 1)),
            ),
            (
                "IPv4",
                vec![0x06, 10, 0, 0, 42],
                TypedData::IPv4(Ipv4Addr::new(10, 0, 0, 42)),
            ),
            // Type 7: IPv6 address: 0x07 followed by 16 bytes, e.g. ::1.
            (
                "IPv6",
                {
                    let mut v = vec![0x07];
                    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                    v
                },
                TypedData::IPv6(Ipv6Addr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
            ),
            // Use arbitrary IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
            (
                "IPv6",
                {
                    let mut v = vec![0x07];
                    // IPv6 address bytes in network order.
                    // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
                    v.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e,
                        0x03, 0x70, 0x73, 0x34,
                    ]);
                    v
                },
                TypedData::IPv6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
                )),
            ),
            // Type 8: String: 0x08, then varint length (5), then "hello".
            (
                "String",
                vec![0x08, 0x05, b'h', b'e', b'l', b'l', b'o'],
                TypedData::String("hello".to_string()),
            ),
            // Type 9: Binary: 0x09, then varint length (3), then bytes 0xAA, 0xBB, 0xCC.
            (
                "Binary",
                vec![0x09, 0x03, 0xAA, 0xBB, 0xCC],
                TypedData::Binary(vec![0xAA, 0xBB, 0xCC]),
            ),
        ];

        for (desc, input, expected) in test_cases {
            let (rest, parsed) = typed_data(&input)
                .unwrap_or_else(|e| panic!("Test case '{}' failed: {:?}", desc, e));
            assert!(
                rest.is_empty(),
                "Test case '{}' did not consume all input: remaining {:?}",
                desc,
                rest
            );
            assert_eq!(parsed, expected, "Test case '{}' failed", desc);
        }
    }
}
