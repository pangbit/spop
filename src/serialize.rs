use crate::frame::{Frame, FramePayload, FrameType};
use nom::number::complete::be_u32;

pub fn serialize_frame(frame: &Frame) -> Vec<u8> {
    let mut bytes = Vec::new();

    let frame_length = calculate_frame_length(&frame);
    bytes.extend_from_slice(&frame_length.to_be_bytes()); // 4-byte frame length
    bytes.push(frame.frame_type as u8); // 1-byte frame type
    bytes.extend_from_slice(&frame.flags.to_be_bytes()); // 4-byte flags
    bytes.extend_from_slice(&frame.stream_id.to_be_bytes()); // 4-byte stream ID
    bytes.extend_from_slice(&frame.frame_id.to_be_bytes()); // 4-byte frame ID

    // Serialize the payload
    match &frame.payload {
        FramePayload::KeyValuePairs(kvs) => {
            for (key, value) in kvs {
                bytes.push(*key); // 1-byte key ID
                bytes.extend_from_slice(&value.to_bytes()); // Serialized value
            }
        }
        FramePayload::Messages(messages) => {
            for msg in messages {
                bytes.extend(msg.to_bytes());
            }
        }
        FramePayload::Actions(actions) => {
            for action in actions {
                bytes.extend(action.to_bytes());
            }
        }
    }

    bytes
}

// Calculates frame length (excluding the first 4 bytes for frame length itself)
fn calculate_frame_length(frame: &Frame) -> u32 {
    let mut length = 13; // Fixed frame header size

    match &frame.payload {
        FramePayload::KeyValuePairs(kvs) => {
            for (_, value) in kvs {
                length += 1 + value.to_bytes().len(); // 1-byte key ID + value size
            }
        }
        FramePayload::Messages(messages) => {
            for msg in messages {
                length += msg.to_bytes().len();
            }
        }
        FramePayload::Actions(actions) => {
            for action in actions {
                length += action.to_bytes().len();
            }
        }
    }

    length
}
