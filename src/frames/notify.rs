use crate::{
    SpopFrame,
    frame::{FramePayload, FrameType, Message, Metadata},
};

// 3.2.6. Frame: NOTIFY
// ---------------------
//
// Information are sent to the agents inside NOTIFY frames. These frames are
// attached to a stream, so STREAM-ID and FRAME-ID must be set. The payload of
// NOTIFY frames is a LIST-OF-MESSAGES.
//
// NOTIFY frames must be acknowledge by agents sending an ACK frame, repeating
// right STREAM-ID and FRAME-ID.
#[derive(Debug)]
pub struct NotifyFrame {
    pub metadata: Metadata,
    pub messages: Vec<Message>,
}

impl SpopFrame for NotifyFrame {
    fn frame_type(&self) -> &FrameType {
        &FrameType::Notify
    }

    fn metadata(&self) -> Metadata {
        self.metadata.clone()
    }

    fn payload(&self) -> FramePayload {
        FramePayload::ListOfMessages(self.messages.clone())
    }
}
