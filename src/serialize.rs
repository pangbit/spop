use crate::frame::{Frame, FramePayload, FrameType};
use crate::types::TypedData;
use std::io::Result;

// Encoding a varint
fn encode_varint(i: u64) -> Vec<u8> {
    let mut buf = Vec::new();

    if i < 240 {
        buf.push(i as u8);
    } else {
        buf.push((i | 240) as u8);
        let mut i = (i - 240) >> 4;

        while i >= 128 {
            buf.push((i | 128) as u8);
            i = (i - 128) >> 7;
        }

        buf.push(i as u8);
    }

    buf
}

/// Structure representing an AGENT-HELLO frame
#[derive(Debug)]
pub struct AgentHello {
    pub version: String,
    pub max_frame_size: u32,
    pub capabilities: Vec<String>,
}

impl AgentHello {
    /// Serializes the AGENT-HELLO frame into a `Frame` structure
    pub fn to_frame(&self) -> Frame {
        let key_value_pairs = vec![
            (
                "version".to_string(),
                TypedData::String(self.version.clone()),
            ),
            (
                "max-frame-size".to_string(),
                TypedData::UInt32(self.max_frame_size),
            ),
            (
                "capabilities".to_string(),
                TypedData::String(self.capabilities.join(",")),
            ),
        ];

        Frame {
            frame_type: FrameType::AgentHello,
            flags: 1,
            stream_id: 0,
            frame_id: 0,
            payload: FramePayload::KeyValuePairs(key_value_pairs),
        }
    }

    /// Serializes the AGENT-HELLO frame into a byte vector
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let frame = self.to_frame();
        let mut serialized = Vec::new();

        // Serialize frame type (1 byte)
        serialized.push(frame.frame_type.to_u8());

        // Serialize flags (4 bytes)
        serialized.extend_from_slice(&frame.flags.to_be_bytes());

        // Serialize stream_id and frame_id (both must be 0 for AGENT-HELLO)
        serialized.extend(encode_varint(frame.stream_id));
        serialized.extend(encode_varint(frame.frame_id));

        // Serialize key-value pairs
        // TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
        //
        // x07version\x08\x032.0\x0emax-frame-size\x03\xfc\xf0\x06\x0ccapabilities\x08\x00'
        //
        //     TYPE                       |  ID | DESCRIPTION
        // -----------------------------+-----+----------------------------------
        //    NULL                      |  0  |  NULL   : <0>
        //    Boolean                   |  1  |  BOOL   : <1+FLAG>
        //    32bits signed integer     |  2  |  INT32  : <2><VALUE:varint>
        //    32bits unsigned integer   |  3  |  UINT32 : <3><VALUE:varint>
        //    64bits signed integer     |  4  |  INT64  : <4><VALUE:varint>
        //    32bits unsigned integer   |  5  |  UNIT64 : <5><VALUE:varint>
        //    IPV4                      |  6  |  IPV4   : <6><STRUCT IN_ADDR:4 bytes>
        //    IPV6                      |  7  |  IPV6   : <7><STRUCT IN_ADDR6:16 bytes>
        //    String                    |  8  |  STRING : <8><LENGTH:varint><BYTES>
        //    Binary                    |  9  |  BINARY : <9><LENGTH:varint><BYTES>
        //   10 -> 15  unused/reserved  |  -  |  -
        // -----------------------------+-----+----------------------------------
        if let FramePayload::KeyValuePairs(kv_pairs) = &frame.payload {
            for (key, value) in kv_pairs {
                // <KEY-LENGTH><KEY><VALUE-TYPE><VALUE-LNGTH><VALUE>

                let mut typed_data = Vec::new();

                // use encode_varint for the length of the key
                typed_data.extend(encode_varint(key.len() as u64));

                // serialize the key
                typed_data.extend_from_slice(key.as_bytes());

                match value {
                    TypedData::String(val) => {
                        // STRING: <8><LENGTH:varint><BYTES>
                        typed_data.push(0x08);
                        // use encode_varint for the length of the value
                        typed_data.extend(encode_varint(val.len() as u64));
                        // serialize the value
                        typed_data.extend_from_slice(val.as_bytes());
                    }
                    TypedData::UInt32(val) => {
                        // UINT32: <3><VALUE:varint>
                        typed_data.push(0x03);
                        // use encode_varint for the length of the value
                        typed_data.extend(encode_varint(*val as u64));
                    }
                    _ => {}
                }

                // append to serialized
                serialized.extend(typed_data);
            }
        }

        // Prepend frame length (4-byte network order)
        let frame_len = serialized.len() as u32;
        let mut output = frame_len.to_be_bytes().to_vec();
        output.extend(serialized);

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_varint; // Import parse_varint

    #[test]
    fn test_encode_decode_varint() {
        // Test cases to cover all different byte ranges
        let test_values: Vec<u64> = vec![
            0,           // 1 byte
            239,         // 1 byte
            240,         // 2 bytes
            2287,        // 2 bytes
            2288,        // 3 bytes
            264432,      // 4 bytes
            4328786160,  // 5 bytes
            10000000000, // Large value
        ];

        for &value in &test_values {
            // Encode the value
            let encoded = encode_varint(value);

            // Decode the encoded value
            let (remaining_input, decoded) = parse_varint(&encoded).unwrap();

            // Assert that the decoded value matches the original
            assert_eq!(value, decoded);

            // Ensure there is no extra data left after decoding
            assert!(
                remaining_input.is_empty(),
                "Remaining input should be empty"
            );
        }
    }

    #[test]
    fn test_encode_decode_varint_loop() {
        // Test encoding and decoding a large number of values
        for i in 0..300000 {
            let encoded = encode_varint(i);
            let (remaining_input, decoded) = parse_varint(&encoded).unwrap();
            assert_eq!(i, decoded, "Failed for value: {}", i);
            assert!(remaining_input.is_empty());
        }
    }
}
