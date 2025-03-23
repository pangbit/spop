use crate::types::TypedData;

#[derive(Debug)]
pub enum FrameType {
    Hello,
    Notify,
    Ack,
    Unknown(u8),
}

#[derive(Debug)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u32,
    pub stream_id: u32,
    pub frame_id: u32,
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
