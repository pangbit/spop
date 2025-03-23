use crate::frame::{Frame, FramePayload, FrameType};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u32};

pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Frame> {
    let (input, frame_length) = be_u32(input)?; // Read 4-byte frame length
    let (input, frame_type) = be_u8(input)?; // Read 1-byte frame type
    let (input, flags) = be_u32(input)?; // Read 4-byte flags
    let (input, stream_id) = be_u32(input)?; // Read stream ID
    let (input, frame_id) = be_u32(input)?; // Read frame ID
    let (input, _payload_bytes) = take(frame_length - 13)(input)?; // Remaining bytes are payload

    let frame = Frame {
        frame_type: match frame_type {
            1 => FrameType::Hello,
            2 => FrameType::Notify,
            3 => FrameType::Ack,
            _ => FrameType::Unknown(frame_type),
        },
        flags,
        stream_id,
        frame_id,
        payload: FramePayload::KeyValuePairs(vec![]), // Placeholder (needs a full parser)
    };

    Ok((input, frame))
}
