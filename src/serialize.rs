use crate::encode_varint; // Import encode_varint
use crate::frame::{Frame, FramePayload, FrameType};
use crate::types::TypedData;
use std::io::Result;

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

/// Serializes an Agent ACK frame.
///
/// The ACK frame acknowledges a NOTIFY frame. It uses the same stream_id and frame_id
/// as the NOTIFY. For this example, we assume an empty payload.
pub fn serialize_ack(stream_id: u64, frame_id: u64) -> Vec<u8> {
    let frame_type: u8 = 103; // ACK frame type
    let flags: u8 = 0; // Typically, ACK might not need extra flags.
    let payload: Vec<u8> = Vec::new();
    let payload_len = payload.len() as u32;

    // Suppose our frame header is defined as:
    // [ frame_type (1 byte) | flags (1 byte) | stream_id (4 bytes) | frame_id (4 bytes) | payload_length (4 bytes) ]
    let mut buf = Vec::with_capacity(1 + 1 + 4 + 4 + 4 + payload.len());
    buf.push(frame_type);
    buf.push(flags);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&frame_id.to_be_bytes());
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}
