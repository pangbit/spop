//! # SPOP Library for parsing HAProxy SPOP (Stream Processing Offload Protocol)
//!
//! <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt>
//!
//! This crate provides structures, traits, and utilities for working with the SPOP protocol frames,
//! including the ability to serialize/deserialize frames and handle various frame types such as
//! `AgentHello`, `HaproxyHello`, and `Ack`. It supports both Unix and TCP-based transports
//! and provides utilities for creating, parsing, and manipulating SPOP frames.
pub mod frames;
pub mod parser;

pub mod actions;
pub use self::actions::{Action, VarScope};

pub mod frame;
pub use self::frame::{Frame, FrameFlags, FramePayload, FrameType, Metadata};

pub mod types;
pub use self::types::TypedData;

pub mod varint;
pub use self::varint::{decode_varint, encode_varint};

/// core trait for the SPOP frame
pub trait SpopFrame: std::fmt::Debug + Send {
    fn frame_type(&self) -> &FrameType;
    fn metadata(&self) -> Metadata;
    fn payload(&self) -> FramePayload;
}

/// trait for serializing SPOP frames
pub trait SpopFrameExt: SpopFrame {
    fn serialize(&self) -> std::io::Result<Vec<u8>> {
        let mut serialized = Vec::new();

        // frame type (1 byte)
        serialized.push(self.frame_type().to_u8());

        // Metadata
        serialized.extend(self.metadata().serialize());

        // payload
        encode_payload(&self.payload(), &mut serialized)?;

        // Prepend frame length
        let frame_len = serialized.len() as u32;
        let mut output = frame_len.to_be_bytes().to_vec();
        output.extend(serialized);

        Ok(output)
    }
}

/// Blanket implementation: any type implementing SpopFrame gets SpopFrameExt automatically.
impl<T: SpopFrame> SpopFrameExt for T {}

/// Helper function to encode the payload.
/// It supports ListOfActions and KVList payloads.
fn encode_payload(payload: &FramePayload, buf: &mut Vec<u8>) -> std::io::Result<()> {
    match payload {
        FramePayload::ListOfActions(actions) => {
            // ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>

            for action in actions {
                match action {
                    Action::SetVar { scope, name, value } => {
                        // Action type: SET-VAR (1 byte)
                        buf.push(0x01);

                        // Number of arguments: 3 (1 byte)
                        buf.push(0x03);

                        // Scope (1 byte)
                        buf.push(scope.to_u8());

                        // Serialize variable name (length + bytes)
                        buf.extend(encode_varint(name.len() as u64));
                        buf.extend_from_slice(name.as_bytes());

                        // Serialize variable value based on type
                        match value {
                            TypedData::String(val) => {
                                buf.push(0x08); // STRING type
                                buf.extend(encode_varint(val.len() as u64));
                                buf.extend_from_slice(val.as_bytes());
                            }
                            TypedData::UInt32(val) => {
                                buf.push(0x03); // UINT32 type
                                buf.extend(encode_varint(*val as u64));
                            }
                            _ => {} // Handle other types if needed
                        }
                    }
                    Action::UnSetVar { scope, name } => {
                        // Action type: UNSET-VAR (1 byte)
                        buf.push(0x02);

                        // Number of arguments: 2 (1 byte)
                        buf.push(0x02);

                        // Scope (1 byte)
                        buf.push(scope.to_u8());

                        // Serialize variable name (length + bytes)
                        buf.extend(encode_varint(name.len() as u64));
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
            }
        }

        FramePayload::KVList(kv_pairs) => {
            for (key, value) in kv_pairs {
                // <KEY-LENGTH><KEY><VALUE-TYPE><VALUE-LNGTH><VALUE>

                // use encode_varint for the length of the key
                buf.extend(encode_varint(key.len() as u64));

                // serialize the key
                buf.extend_from_slice(key.as_bytes());

                match value {
                    TypedData::String(val) => {
                        // STRING: <8><LENGTH:varint><BYTES>
                        buf.push(0x08);
                        // use encode_varint for the length of the value
                        buf.extend(encode_varint(val.len() as u64));
                        // serialize the value
                        buf.extend_from_slice(val.as_bytes());
                    }
                    TypedData::UInt32(val) => {
                        // UINT32: <3><VALUE:varint>
                        buf.push(0x03);
                        // use encode_varint for the length of the value
                        buf.extend(encode_varint(*val as u64));
                    }
                    _ => {}
                }
            }
        }

        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported frame payload type",
            ));
        }
    }

    Ok(())
}
