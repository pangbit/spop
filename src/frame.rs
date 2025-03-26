use crate::{encode_varint, types::TypedData};
use nom::error::ErrorKind;

// 3.2.2. Frame types overview
// ----------------------------
//
// Here are types of frame supported by SPOE. Frames sent by HAProxy come first,
// then frames sent by agents :
//
//     TYPE                       |  ID | DESCRIPTION
//   -----------------------------+-----+-------------------------------------
//      HAPROXY-HELLO             |  1  |  Sent by HAProxy when it opens a
//                                |     |  connection on an agent.
//                                |     |
//      HAPROXY-DISCONNECT        |  2  |  Sent by HAProxy when it want to close
//                                |     |  the connection or in reply to an
//                                |     |  AGENT-DISCONNECT frame
//                                |     |
//      NOTIFY                    |  3  |  Sent by HAProxy to pass information
//                                |     |  to an agent
//   -----------------------------+-----+-------------------------------------
//      AGENT-HELLO               | 101 |  Reply to a HAPROXY-HELLO frame, when
//                                |     |  the connection is established
//                                |     |
//      AGENT-DISCONNECT          | 102 |  Sent by an agent just before closing
//                                |     |  the connection
//                                |     |
//      ACK                       | 103 |  Sent to acknowledge a NOTIFY frame
//   -----------------------------+-----+-------------------------------------
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum FrameType {
    HaproxyHello = 1,
    HaproxyDisconnect = 2,
    Notify = 3,
    AgentHello = 101,
    AgentDisconnect = 102,
    Ack = 103,
}

impl FrameType {
    pub const fn from_u8(value: u8) -> Result<Self, ErrorKind> {
        match value {
            1 => Ok(Self::HaproxyHello),
            2 => Ok(Self::HaproxyDisconnect),
            3 => Ok(Self::Notify),
            101 => Ok(Self::AgentHello),
            102 => Ok(Self::AgentDisconnect),
            103 => Ok(Self::Ack),
            _ => Err(ErrorKind::Alt),
        }
    }

    /// Converts FrameType to its corresponding u8 value
    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::HaproxyHello => 1,
            Self::HaproxyDisconnect => 2,
            Self::Notify => 3,
            Self::AgentHello => 101,
            Self::AgentDisconnect => 102,
            Self::Ack => 103,
        }
    }
}

// Exchange between HAProxy and agents are made using FRAME packets. All frames
// must be prefixed with their size encoded on 4 bytes in network byte order:
//
//     <FRAME-LENGTH:4 bytes> <FRAME>
//
// A frame always starts with its type, on one byte, followed by metadata
// containing flags, on 4 bytes and a two variable-length integer representing the
// stream identifier and the frame identifier inside the stream:
//
//     FRAME       : <FRAME-TYPE:1 byte> <METADATA> <FRAME-PAYLOAD>
//     METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
//
#[derive(Debug)]
pub struct Frame {
    pub frame_type: FrameType,
    pub metadata: Metadata,
    pub payload: FramePayload,
}

impl Frame {
    pub const fn new(frame_type: FrameType, metadata: Metadata, payload: FramePayload) -> Self {
        Self {
            frame_type,
            metadata,
            payload,
        }
    }

    pub fn serialize(&self) -> std::io::Result<Vec<u8>> {
        let mut serialized = Vec::new();

        // Serialize frame type (1 byte)
        serialized.push(self.frame_type.to_u8());

        // Serialize metadata
        serialized.extend(self.metadata.serialize());

        // Serialize payload
        match &self.payload {
            FramePayload::ListOfMessages(_messages) => {
                serialized.push(0x01); // LIST-OF-MESSAGES
            }
            FramePayload::ListOfActions(actions) => {
                // ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>

                for action in actions {
                    match action {
                        Action::SetVar { scope, name, value } => {
                            let mut action_data = Vec::new();

                            // Action type: SET-VAR (1 byte)
                            action_data.push(0x01);

                            // Number of arguments: 3 (1 byte)
                            action_data.push(0x03);

                            // Scope (1 byte)
                            action_data.push(scope.to_u8());

                            // Serialize variable name (length + bytes)
                            action_data.extend(encode_varint(name.len() as u64));
                            action_data.extend_from_slice(name.as_bytes());

                            // Serialize variable value based on type
                            match value {
                                TypedData::String(val) => {
                                    action_data.push(0x08); // STRING type
                                    action_data.extend(encode_varint(val.len() as u64));
                                    action_data.extend_from_slice(val.as_bytes());
                                }
                                TypedData::UInt32(val) => {
                                    action_data.push(0x03); // UINT32 type
                                    action_data.extend(encode_varint(*val as u64));
                                }
                                _ => {} // Handle other types if needed
                            }

                            // Append serialized action
                            serialized.extend(action_data);
                        }
                        _ => todo!(),
                    }
                }
            }
            FramePayload::KVList(kv_pairs) => {
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
        }

        // Prepend frame length
        let frame_len = serialized.len() as u32;
        let mut output = frame_len.to_be_bytes().to_vec();
        output.extend(serialized);

        Ok(output)
    }
}

// METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
#[derive(Debug)]
pub struct Metadata {
    pub flags: FrameFlags,
    pub stream_id: u64,
    pub frame_id: u64,
}

impl Metadata {
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        // Serialize flags (4 bytes)
        serialized.extend_from_slice(&self.flags.to_be_bytes());

        // Serialize stream_id and frame_id (both encoded as varint)
        serialized.extend(encode_varint(self.stream_id));
        serialized.extend(encode_varint(self.frame_id));

        serialized
    }
}

// Then comes the frame payload. Depending on the frame type, the payload can be
// of three types: a simple key/value list, a list of messages or a list of
// actions.
//
//     FRAME-PAYLOAD    : <LIST-OF-MESSAGES> | <LIST-OF-ACTIONS> | <KV-LIST>
//
//     LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
//     MESSAGE-NAME     : <STRING>
//
//     LIST-OF-ACTIONS  : [ <ACTION-TYPE:1 byte> <NB-ARGS:1 byte> <ACTION-ARGS> ... ]
//     ACTION-ARGS      : [ <TYPED-DATA>... ]
//
//     KV-LIST          : [ <KV-NAME> <KV-VALUE> ... ]
//     KV-NAME          : <STRING>
//     KV-VALUE         : <TYPED-DATA>
#[derive(Debug)]
pub enum FramePayload {
    ListOfMessages(Vec<Message>),
    ListOfActions(Vec<Action>),
    KVList(Vec<(String, TypedData)>),
}

#[derive(Debug)]
pub struct Message {
    pub name: String,
    pub args: Vec<(String, TypedData)>,
}

// 3.4. Actions
// -------------
//
// An agent must acknowledge each NOTIFY frame by sending the corresponding ACK
// frame. Actions can be added in these frames to dynamically take action on the
// processing of a stream.
//
// Here is the list of supported actions:
//
//   * set-var    set the value for an existing variable. 3 arguments must be
//                attached to this action: the variable scope (proc, sess, txn,
//                req or res), the variable name (a string) and its value.
//
//     ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>
//
//     SET-VAR     : <1>
//     NB-ARGS     : <3>
//     VAR-SCOPE   : <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
//     VAR-NAME    : <STRING>
//     VAR-VALUE   : <TYPED-DATA>
//
//     PROCESS     : <0>
//     SESSION     : <1>
//     TRANSACTION : <2>
//     REQUEST     : <3>
//     RESPONSE    : <4>
//
//   * unset-var    unset the value for an existing variable. 2 arguments must be
//                  attached to this action: the variable scope (proc, sess, txn,
//                  req or res) and the variable name (a string).
//
//     ACTION-UNSET-VAR  : <UNSET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME>
//
//     UNSET-VAR   : <2>
//     NB-ARGS     : <2>
//     VAR-SCOPE   : <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
//     VAR-NAME    : <STRING>
//
//     PROCESS     : <0>
//     SESSION     : <1>
//     TRANSACTION : <2>
//     REQUEST     : <3>
//     RESPONSE    : <4>
//
//
// NOTE: Name of the variables will be automatically prefixed by HAProxy to avoid
//       name clashes with other variables used in HAProxy. Moreover, unknown
//       variable will be silently ignored.
#[derive(Debug, Clone)]
pub enum VarScope {
    Process = 0,
    Session = 1,
    Transaction = 2,
    Request = 3,
    Response = 4,
}

impl VarScope {
    /// Converts FrameType to its corresponding u8 value
    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Process => 0,
            Self::Session => 1,
            Self::Transaction => 2,
            Self::Request => 3,
            Self::Response => 4,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    SetVar {
        scope: VarScope,
        name: String,
        value: TypedData,
    },
    UnSetVar {
        scope: VarScope,
        name: String,
    },
}

//
// #[derive(Debug)]
// pub struct Action {
//     pub action_type: u8,
//     pub args: Vec<TypedData>,
// }

#[derive(Debug)]
pub struct FrameFlags(u32);

impl FrameFlags {
    pub const fn new(is_fin: bool, is_abort: bool) -> Self {
        let mut flags = 0u32;

        if is_fin {
            flags |= 0x00000001;
        }

        if is_abort {
            flags |= 0x00000002;
        }

        Self(flags)
    }

    pub const fn is_fin(&self) -> bool {
        self.0 & 0x00000001u32 != 0
    }

    pub const fn is_abort(&self) -> bool {
        self.0 & 0x00000002u32 != 0
    }

    /// Parses FrameFlags from a 4-byte network order field
    pub const fn from_u32(value: u32) -> Result<Self, ErrorKind> {
        // Ensure FIN is always set (per protocol spec)
        if value & 0x00000001 == 0 {
            return Err(ErrorKind::Verify); // Equivalent to "validation failed"
        }

        // Ensure only valid bits are set (optional strict check)
        if value & 0xFFFFFFFC != 0 {
            return Err(ErrorKind::Alt); // Invalid reserved bits used
        }

        Ok(Self(value))
    }

    pub const fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0), Err(ErrorKind::Alt));
        assert_eq!(FrameType::from_u8(1), Ok(FrameType::HaproxyHello));
        assert_eq!(FrameType::from_u8(2), Ok(FrameType::HaproxyDisconnect));
        assert_eq!(FrameType::from_u8(3), Ok(FrameType::Notify));
        assert_eq!(FrameType::from_u8(101), Ok(FrameType::AgentHello));
        assert_eq!(FrameType::from_u8(102), Ok(FrameType::AgentDisconnect));
        assert_eq!(FrameType::from_u8(103), Ok(FrameType::Ack));
    }

    #[test]
    fn test_frame_type_to_u8() {
        assert_eq!(FrameType::HaproxyHello.to_u8(), 1);
        assert_eq!(FrameType::HaproxyDisconnect.to_u8(), 2);
        assert_eq!(FrameType::Notify.to_u8(), 3);
        assert_eq!(FrameType::AgentHello.to_u8(), 101);
        assert_eq!(FrameType::AgentDisconnect.to_u8(), 102);
        assert_eq!(FrameType::Ack.to_u8(), 103);
    }

    #[test]
    fn test_frameflags() {
        let flags = FrameFlags(0x00000001);
        assert_eq!(flags.is_fin(), true);

        let flags = FrameFlags(0x00000000);
        assert_eq!(flags.is_fin(), false);

        let flags = FrameFlags(0x00000002);
        assert_eq!(flags.is_abort(), true);

        let flags = FrameFlags(0x00000003);
        assert_eq!(flags.is_fin(), true);
        assert_eq!(flags.is_abort(), true);
    }

    #[test]
    fn test_frameflags_new() {
        let flags = FrameFlags::new(true, false);
        assert_eq!(flags.0, 0x00000001);

        let flags = FrameFlags::new(false, true);
        assert_eq!(flags.0, 0x00000002);

        let flags = FrameFlags::new(true, true);
        assert_eq!(flags.0, 0x00000003);
    }
}
