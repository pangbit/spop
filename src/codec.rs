use bytes::{BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

use crate::SpopFrame;
use crate::parser::parse_frame;

pub struct SpopCodec;

impl Decoder for SpopCodec {
    type Item = Box<dyn SpopFrame>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Box<dyn SpopFrame>>, Self::Error> {
        match parse_frame(src) {
            Ok((_, frame)) => Ok(Some(frame)),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to parse frame",
            )),
        }
    }
}

impl Encoder<Box<dyn SpopFrame>> for SpopCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: Box<dyn SpopFrame>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        println!("Encoding frame: {:?}", frame.frame_type());

        let serialized = frame.serialize()?;

        println!("Serialized AgentHello bytes: {:?}", serialized);

        dst.put_slice(&serialized);

        Ok(())
    }
}
