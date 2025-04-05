use crate::{
    SpopFrame,
    frame::{FrameFlags, FramePayload, FrameType, Message, Metadata},
    frames::haproxy_disconnect::{HaproxyDisconnect, HaproxyDisconnectFrame},
    frames::haproxy_hello::{HaproxyHello, HaproxyHelloFrame},
    frames::notify::NotifyFrame,
    types::{TypedData, typed_data},
    varint::decode_varint,
};
use nom::{
    Err, IResult, Parser,
    bytes::complete::take,
    combinator::{all_consuming, complete},
    error::{Error, ErrorKind},
    multi::{many_m_n, many0},
    number::streaming::{be_u8, be_u32},
};
use std::collections::HashMap;

// https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt
pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Box<dyn SpopFrame>> {
    // Exchange between HAProxy and agents are made using FRAME packets. All frames must be
    // prefixed with their size encoded on 4 bytes in network byte order:
    // <FRAME-LENGTH:4 bytes> <FRAME>
    //
    let (input, frame_length) = be_u32(input)?;

    // Extract only frame body
    let (remaining, frame) = take(frame_length)(input)?;

    // check if the frame length is correct
    if frame.len() != frame_length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    //A frame always starts with its type, on one byte, followed by metadata containing flags, on 4
    //bytes and a two variable-length integer representing the stream identifier and the frame
    //identifier inside the stream:
    //
    // FRAME       : <FRAME-TYPE:1 byte> <METADATA> <FRAME-PAYLOAD>
    let (frame, frame_type_byte) = be_u8(frame)?; // Read 1-byte frame type

    // Convert the byte to a FrameType
    let frame_type = FrameType::from_u8(frame_type_byte)
        .map_err(|_| Err::Error(Error::new(input, ErrorKind::Alt)))?;

    // METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
    let (frame, flags_value) = be_u32(frame)?; // Read 4-byte flags

    // Convert the flags to a FrameFlags
    let flags = FrameFlags::from_u32(flags_value)
        .map_err(|_| Err::Error(Error::new(input, ErrorKind::Alt)))?;

    if flags.is_abort() {
        return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
    }

    let (frame, stream_id) = decode_varint(frame)?;
    let (frame, frame_id) = decode_varint(frame)?;

    // Create the metadata structure
    let metadata = Metadata {
        flags,
        stream_id,
        frame_id,
    };

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
    //
    let frame_payload = frame;

    match frame_type {
        // 3.2.4. Frame: HAPROXY-HELLO
        // This frame is the first one exchanged between HAProxy and an agent, when the connection
        // is established.
        //
        // The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set 0.
        FrameType::HaproxyHello => {
            let mut parser = all_consuming(parse_key_value_pairs);

            let (_, payload) = parser.parse(frame_payload)?;

            // check mandatory items
            let hello = HaproxyHello::try_from(payload)
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;

            let frame = HaproxyHelloFrame {
                metadata,
                payload: hello,
            };

            Ok((remaining, Box::new(frame)))
        }

        // 3.2.8. Frame: HAPROXY-DISCONNECT
        // If an error occurs, at anytime, from the HAProxy side, a HAPROXY-DISCONNECT frame is
        // sent with information describing the error. HAProxy will wait an AGENT-DISCONNECT frame
        // in reply. All other frames will be ignored. The agent must then close the socket.
        //
        // The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set 0.
        FrameType::HaproxyDisconnect => {
            let mut parser = all_consuming(parse_key_value_pairs);

            let (_, payload) = parser.parse(frame_payload)?;

            // check mandatory items
            let disconnect = HaproxyDisconnect::try_from(payload)
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;

            let frame = HaproxyDisconnectFrame {
                metadata,
                payload: disconnect,
            };

            Ok((remaining, Box::new(frame)))
        }

        // 3.2.6. Frame: NOTIFY
        // Information are sent to the agents inside NOTIFY frames. These frames are attached to a
        // stream, so STREAM-ID and FRAME-ID must be set.
        //
        // The payload of NOTIFY frames is a LIST-OF-MESSAGES.
        FrameType::Notify => {
            let mut parser = all_consuming(parse_list_of_messages);

            let (_, messages) = parser.parse(frame_payload)?;

            let frame = NotifyFrame { metadata, messages };

            Ok((remaining, Box::new(frame)))
        }

        // Unknown frames may be silently skipped or trigger an error, depending on the
        // implementation.
        _ => Err(nom::Err::Failure(Error::new(input, ErrorKind::NoneOf))),
    }
}

/// Parse entire KV-LIST payload
fn parse_key_value_pairs(input: &[u8]) -> IResult<&[u8], FramePayload> {
    // Create the parser combinator chain
    let mut parser = all_consuming(many0(complete(parse_key_value_pair)));

    // Execute the parser with the input
    let (input, pairs) = parser.parse(input)?;

    let mut map = HashMap::new();

    // handle duplicate keys
    for (key, value) in pairs {
        if map.contains_key(&key) {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
        }
        map.insert(key, value);
    }

    Ok((input, FramePayload::KVList(map)))
}

/// Parse a key-value pair (used in KV-LIST)
/// A KV-LIST is a list of key/value pairs. Each pair is made of:
/// - a name (STRING)
/// - a value (TYPED-DATA)
fn parse_key_value_pair(input: &[u8]) -> IResult<&[u8], (String, TypedData)> {
    // KV-NAME is a <STRING> (varint length + bytes)
    let (input, key) = parse_string(input)?;

    // Ensure we have at least 1 byte left for the type
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    // KV-VALUE is a <TYPED-DATA>
    let (input, value) = typed_data(input)?;

    Ok((input, (key, value)))
}

/// Parse a length-prefixed string
fn parse_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = decode_varint(input)?;

    if input.len() < length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, bytes) = take(length)(input)?;

    String::from_utf8(bytes.to_vec())
        .map(|s| (input, s))
        .map_err(|_| nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

/// Parse entire list of messages payload
///
/// LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
/// MESSAGE-NAME     : <STRING>
fn parse_list_of_messages(input: &[u8]) -> IResult<&[u8], Vec<Message>> {
    let (remaining, message) = parse_string(input)?;

    let (remaining, nb_args_bytes) = take(1usize)(remaining)?;

    let nb_args = nb_args_bytes[0] as usize;

    let mut parser = all_consuming(many_m_n(nb_args, nb_args, parse_key_value_pair));

    let (remaining, kv_list) = parser.parse(remaining)?;

    let mut map = HashMap::new();

    // handle duplicate keys
    for (key, value) in kv_list {
        if map.contains_key(&key) {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
        }
        map.insert(key, value);
    }

    let msg = Message {
        name: message,
        args: map,
    };

    Ok((remaining, vec![msg]))
}
