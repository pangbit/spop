use crate::types::TypedData;

#[derive(Debug)]
pub enum FrameType {
    HaproxyHello,      // 1
    HaproxyDisconnect, // 2
    Notify,            // 3
    AgentHello,        // 101
    AgentDisconnect,   // 102
    Ack,               // 103
    Unknown(u8),       // Catch-all for unsupported types
}

impl FrameType {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::HaproxyHello,
            2 => Self::HaproxyDisconnect,
            3 => Self::Notify,
            101 => Self::AgentHello,
            102 => Self::AgentDisconnect,
            103 => Self::Ack,
            other => Self::Unknown(other),
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
            Self::Unknown(val) => *val,
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u32,
    pub stream_id: u64,
    pub frame_id: u64,
    pub payload: FramePayload,
}

#[derive(Debug)]
pub enum FramePayload {
    Messages(Vec<Message>),
    Actions(Vec<Action>),
    KeyValuePairs(Vec<(String, TypedData)>),
}

#[derive(Debug)]
pub struct Message {
    pub name: String,
}

#[derive(Debug)]
pub struct Action {
    pub action_type: u8,
    pub args: Vec<TypedData>,
}
