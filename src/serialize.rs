use crate::frame::{Action, Frame, FrameFlags, FramePayload, FrameType, Metadata, VarScope};
use crate::types::TypedData;

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
            metadata: Metadata {
                flags: FrameFlags::new(true, false), // FIN flag set, ABORT flag not set
                stream_id: 0,
                frame_id: 0,
            },
            payload: FramePayload::KVList(key_value_pairs),
        }
    }
}

/// Structure representing an ACK frame
#[derive(Debug)]
pub struct Ack {
    pub stream_id: u64,
    pub frame_id: u64,
    pub actions: Vec<Action>,
}

impl Ack {
    /// Creates a new ACK frame with no actions
    pub const fn new(stream_id: u64, frame_id: u64) -> Self {
        Self {
            stream_id,
            frame_id,
            actions: Vec::new(),
        }
    }

    /// Adds a set-var action to the ACK frame
    pub fn set_var(mut self, scope: VarScope, name: &str, value: TypedData) -> Self {
        self.actions.push(Action::SetVar {
            scope,
            name: name.to_string(),
            value,
        });
        self
    }

    /// Serializes the ACK frame into a `Frame` structure
    pub fn to_frame(&self) -> Frame {
        Frame {
            frame_type: FrameType::Ack,
            metadata: Metadata {
                flags: FrameFlags::new(true, false), // FIN flag set, ABORT flag not set
                stream_id: self.stream_id,
                frame_id: self.frame_id,
            },
            payload: FramePayload::ListOfActions(self.actions.clone()), // Empty payload for ACK
        }
    }
}
