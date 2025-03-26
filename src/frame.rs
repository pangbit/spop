use crate::types::TypedData;

#[derive(Debug, Eq, PartialEq)]
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
    pub args: Vec<(String, TypedData)>,
}

#[derive(Debug)]
pub struct Action {
    pub action_type: u8,
    pub args: Vec<TypedData>,
}

#[derive(Debug)]
pub struct FrameFlags(u32);

impl FrameFlags {
    pub fn is_fin(&self) -> bool {
        self.0 & 0x00000001u32 != 0
    }

    pub fn is_abort(&self) -> bool {
        self.0 & 0x00000002u32 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(1), FrameType::HaproxyHello);
        assert_eq!(FrameType::from_u8(2), FrameType::HaproxyDisconnect);
        assert_eq!(FrameType::from_u8(3), FrameType::Notify);
        assert_eq!(FrameType::from_u8(101), FrameType::AgentHello);
        assert_eq!(FrameType::from_u8(102), FrameType::AgentDisconnect);
        assert_eq!(FrameType::from_u8(103), FrameType::Ack);
        assert_eq!(FrameType::from_u8(0), FrameType::Unknown(0));
    }

    #[test]
    fn test_frame_type_to_u8() {
        assert_eq!(FrameType::HaproxyHello.to_u8(), 1);
        assert_eq!(FrameType::HaproxyDisconnect.to_u8(), 2);
        assert_eq!(FrameType::Notify.to_u8(), 3);
        assert_eq!(FrameType::AgentHello.to_u8(), 101);
        assert_eq!(FrameType::AgentDisconnect.to_u8(), 102);
        assert_eq!(FrameType::Ack.to_u8(), 103);
        assert_eq!(FrameType::Unknown(0).to_u8(), 0);
    }

    #[test]
    fn test_frame_type_from_u8_binary() {
        let data = vec![1, 2, 3, 101, 102, 103, 0];
        let expected = vec![
            FrameType::HaproxyHello,
            FrameType::HaproxyDisconnect,
            FrameType::Notify,
            FrameType::AgentHello,
            FrameType::AgentDisconnect,
            FrameType::Ack,
            FrameType::Unknown(0),
        ];

        for (i, &val) in data.iter().enumerate() {
            assert_eq!(FrameType::from_u8(val), expected[i]);
        }
    }

    #[test]
    fn test_frameflags() {
        let flags = FrameFlags(0b00000001);
        assert_eq!(flags.is_fin(), true);

        let flags = FrameFlags(0b00000000);
        assert_eq!(flags.is_fin(), false);

        let flags = FrameFlags(0x00000003);
        assert_eq!(flags.is_fin(), true);
        assert_eq!(flags.is_abort(), true);
    }
}
