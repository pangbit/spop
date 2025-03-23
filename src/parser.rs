use crate::{
    frame::{Frame, FramePayload, FrameType, Message},
    types::TypedData,
};
use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{all_consuming, complete},
    error::{Error, ErrorKind},
    multi::{count, many0},
    number::streaming::{be_u8, be_u32, be_u64},
};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

// https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt
pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Frame> {
    // Exchange between HAProxy and agents are made using FRAME packets. All frames must be
    // prefixed with their size encoded on 4 bytes in network byte order:
    // <FRAME-LENGTH:4 bytes> <FRAME>
    //
    let (input, frame_length) = be_u32(input)?;

    // Make sure we have enough data to read the full frame
    if input.len() < frame_length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (remaining, frame_body) = take(frame_length.saturating_sub(4))(input)?;

    //A frame always starts with its type, on one byte, followed by metadata containing flags, on 4
    //bytes and a two variable-length integer representing the stream identifier and the frame
    //identifier inside the stream:
    //
    // FRAME       : <FRAME-TYPE:1 byte> <METADATA> <FRAME-PAYLOAD>
    let (body_remaining, frame_type_byte) = be_u8(frame_body)?; // Read 1-byte frame type

    // METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
    let (body_remaining, flags) = be_u32(body_remaining)?; // Read 4-byte flags
    let (body_remaining, stream_id) = parse_varint(body_remaining)?;
    let (body_remaining, frame_id) = parse_varint(body_remaining)?;

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
    let frame_payload = body_remaining;

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

    let frame_type = FrameType::from_u8(frame_type_byte);

    // In parse_frame
    println!("Frame length: {}", frame_length);
    println!("Frame type: {}, {:#?}", frame_type_byte, frame_type);
    println!("Flags: {}", flags);
    println!("Stream ID: {}", stream_id);
    println!("Frame ID: {}", frame_id);
    println!("Payload size: {}", frame_payload.len());

    let payload = match frame_type {
        // 3.2.4. Frame: HAPROXY-HELLO
        // This frame is the first one exchanged between HAProxy and an agent, when the connection
        // is established.
        //
        // 3.2.8. Frame: HAPROXY-DISCONNECT
        // If an error occurs, at anytime, from the HAProxy side, a HAPROXY-DISCONNECT frame is
        // sent with information describing the error. HAProxy will wait an AGENT-DISCONNECT frame
        // in reply. All other frames will be ignored. The agent must then close the socket.
        //
        // The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set 0.
        FrameType::HaproxyHello | FrameType::HaproxyDisconnect => {
            let mut parser = all_consuming(parse_key_value_pairs);
            let (_, payload) = parser.parse(frame_payload)?;
            payload
        }

        // 3.2.6. Frame: NOTIFY
        // Information are sent to the agents inside NOTIFY frames. These frames are attached to a
        // stream, so STREAM-ID and FRAME-ID must be set.
        //
        // The payload of NOTIFY frames is a LIST-OF-MESSAGES.
        FrameType::Notify => {
            let mut parser = all_consuming(parse_list_of_messages);
            let (_, payload) = parser.parse(frame_payload)?;
            payload
        }

        // Unknown frames may be silently skipped or trigger an error, depending on the
        // implementation.
        _ => return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag))),
    };

    let frame = Frame {
        frame_type,
        flags,
        stream_id,
        frame_id,
        payload,
    };

    Ok((remaining, frame))
}

// Variable-length integer (varint) are encoded using Peers encoding:
//
//
//        0  <= X < 240        : 1 byte  (7.875 bits)  [ XXXX XXXX ]
//       240 <= X < 2288       : 2 bytes (11 bits)     [ 1111 XXXX ] [ 0XXX XXXX ]
//      2288 <= X < 264432     : 3 bytes (18 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]   [ 0XXX XXXX ]
//    264432 <= X < 33818864   : 4 bytes (25 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*2 [ 0XXX XXXX ]
//  33818864 <= X < 4328786160 : 5 bytes (32 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*3 [ 0XXX XXXX ]
//  ...
//
// For booleans, the value (true or false) is the first bit in the FLAGS
// bitfield. if this bit is set to 0, then the boolean is evaluated as false,
// otherwise, the boolean is evaluated as true.
fn parse_varint(input: &[u8]) -> IResult<&[u8], u64> {
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, first) = be_u8(input)?;

    // Simple case: value < 240
    if first < 240 {
        return Ok((input, first as u64));
    }

    // Complex case: multi-byte encoding
    let mut value = (first - 240) as u64;
    let mut shift = 4;

    // Read continuation bytes
    let mut current_input = input;
    loop {
        if current_input.is_empty() {
            return Err(nom::Err::Error(Error::new(current_input, ErrorKind::Eof)));
        }

        let (rest, byte) = be_u8(current_input)?;
        current_input = rest;

        // High bit indicates continuation, low 7 bits are data
        value = (value << 7) | (byte & 0x7F) as u64;

        // If high bit is not set, this is the last byte
        if (byte & 0x80) == 0 {
            break;
        }

        // Safety check to prevent infinite loops
        shift += 7;
        if shift > 64 {
            return Err(nom::Err::Error(Error::new(
                current_input,
                ErrorKind::TooLarge,
            )));
        }
    }

    Ok((current_input, value))
}

/// Parse a TypedData from input bytes
fn parse_typed_data(input: &[u8]) -> IResult<&[u8], TypedData> {
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, type_and_flags) = be_u8(input)?;

    // TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
    //
    // First 4 bits are TYPE, last 4 bits are FLAGS
    let type_id = type_and_flags >> 4;
    let flags = type_and_flags & 0x0F;

    println!(
        "input len: {}, Type ID: {}, Flags: {}",
        input.len(),
        type_id,
        flags
    );

    match type_id {
        0 => Ok((input, TypedData::Null)),
        1 => Ok((input, TypedData::Bool((flags & 1) != 0))),
        2 => parse_varint(input).map(|(i, v)| (i, TypedData::Int32(v as i32))),
        3 => parse_varint(input).map(|(i, v)| (i, TypedData::UInt32(v as u32))),
        4 => parse_varint(input).map(|(i, v)| (i, TypedData::Int64(v as i64))),
        5 => parse_varint(input).map(|(i, v)| (i, TypedData::UInt64(v))),
        6 => {
            if input.len() < 4 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(4usize)(input)?;
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok((input, TypedData::IPv4(addr)))
        }
        7 => {
            if input.len() < 16 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(16usize)(input)?;
            let addr = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
            Ok((input, TypedData::IPv6(addr)))
        }
        8 | 9 => {
            let (input, length) = parse_varint(input)?;

            if input.len() < length as usize {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }

            let (input, data) = take(length)(input)?;
            if type_id == 8 {
                let s = String::from_utf8_lossy(data).into_owned();
                Ok((input, TypedData::String(s)))
            } else {
                Ok((input, TypedData::Binary(data.to_vec())))
            }
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

/// Parse a key-value pair (used in KV-LIST)
/// A KV-LIST is a list of key/value pairs. Each pair is made of:
/// - a name (STRING)
/// - a value (TYPED-DATA)
fn parse_key_value_pair(input: &[u8]) -> IResult<&[u8], (String, TypedData)> {
    // KV-NAME is a <STRING> (varint length + bytes)
    let (input, key) = parse_string(input)?;

    // KV-VALUE is a <TYPED-DATA>
    let (input, value) = parse_typed_data(input)?;

    Ok((input, (key, value)))
}

/// Parse entire KV-LIST payload
fn parse_key_value_pairs(input: &[u8]) -> IResult<&[u8], FramePayload> {
    // Create the parser combinator chain
    let mut parser = all_consuming(many0(complete(parse_key_value_pair)));

    // Execute the parser with the input
    let (input, pairs) = parser.parse(input)?;

    Ok((input, FramePayload::KeyValuePairs(pairs)))
}

/// Parse a length-prefixed string
fn parse_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = parse_varint(input)?;

    if input.len() < length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, bytes) = take(length)(input)?;

    String::from_utf8(bytes.to_vec())
        .map(|s| (input, s))
        .map_err(|_| nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

/// Parse a single argument (name + typed data)
fn parse_argument(input: &[u8]) -> IResult<&[u8], (String, TypedData)> {
    let (input, name) = parse_string(input)?;
    let (input, value) = parse_typed_data(input)?;
    Ok((input, (name, value)))
}

/// Parse message data (name + arguments)
fn parse_message_data(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, name) = parse_string(input)?;
    let (input, num_args) = be_u32(input)?;
    let (input, args) = count(parse_argument, num_args as usize).parse(input)?;
    Ok((input, Message { name, args }))
}

/// Parse a single message with length prefix
fn parse_single_message(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, message_length) = be_u64(input)?;

    if input.len() < message_length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, message_data) = take(message_length)(input)?;
    let (remaining, message) = all_consuming(parse_message_data).parse(message_data)?;

    if !remaining.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::NonEmpty)));
    }

    Ok((input, message))
}

/// Parse entire list of messages payload
fn parse_list_of_messages(input: &[u8]) -> IResult<&[u8], FramePayload> {
    let (input, num_messages) = be_u32(input)?;
    let (input, messages) = count(parse_single_message, num_messages as usize).parse(input)?;
    Ok((input, FramePayload::Messages(messages)))
}
