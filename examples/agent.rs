use anyhow::Result;
use bytes::BytesMut;
use spop::{
    frame::{FramePayload, FrameType},
    parser::parse_frame,
    serialize::{AgentHello, serialize_ack},
    types::TypedData,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:12345").await?;
    println!("SPOE Agent listening on port 12345...");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);
        tokio::spawn(handle_connection(socket));
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(4096);

    loop {
        let n = socket.read_buf(&mut buffer).await?;
        if n == 0 {
            println!("Client disconnected");
            break;
        }

        println!("Buffer: {:X?}", buffer);

        match parse_frame(&buffer) {
            Ok((_, frame)) => {
                println!("Parsed frame: {:?}", frame);

                match frame.frame_type {
                    // Respond with AgentHello frame
                    FrameType::HaproxyHello => {
                        // * "version"    <STRING>
                        // This is the SPOP version the agent supports. It must follow the format
                        // "Major.Minor" and it must be lower or equal than one of major versions
                        // announced by HAProxy.
                        let version = "2.0".to_string();

                        // Extract max-frame-size from the frame payload
                        let mut max_frame_size = 0;
                        if let FramePayload::KeyValuePairs(kv_pairs) = &frame.payload {
                            for (key, value) in kv_pairs {
                                if key == "max-frame-size" {
                                    if let TypedData::UInt32(val) = value {
                                        max_frame_size = *val;
                                    }
                                }
                            }
                        }

                        // Create the AgentHello with the values
                        let agent_hello = AgentHello {
                            version,
                            max_frame_size,
                            capabilities: vec![], // Empty capabilities for now
                        };

                        println!("Sending AgentHello: {:#?}", agent_hello);

                        // Serialize the AgentHello into a Frame
                        match agent_hello.serialize() {
                            Ok(response) => {
                                socket.write_all(&response).await?;
                                socket.flush().await?;
                            }
                            Err(e) => {
                                eprintln!("Failed to serialize response: {:?}", e);
                            }
                        }
                    }

                    // Respond with AgentDisconnect frame
                    FrameType::HaproxyDisconnect => {
                        respond_ok(&mut socket).await?;
                    }

                    // Respond with Ack frame
                    FrameType::Notify => {
                        let serial_id = frame.stream_id;
                        let frame_id = frame.frame_id;
                        let ack = serialize_ack(serial_id, frame_id);
                        socket.write_all(&ack).await?;
                        socket.flush().await?;
                    }

                    _ => {
                        eprintln!("Unsupported frame type: {:?}", frame.frame_type);
                    }
                }
            }

            Err(e) => {
                eprintln!("Failed to parse frame: {:?}", e);
            }
        }

        buffer.clear();
    }

    Ok(())
}

async fn respond_ok(socket: &mut TcpStream) -> Result<()> {
    let response = b"\x00\x00\x00\x04OK\x00"; // SPOE response example
    socket.write_all(response).await?;
    socket.flush().await?;
    Ok(())
}
