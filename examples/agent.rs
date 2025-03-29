use anyhow::Result;
use bytes::BytesMut;
use spop::{
    frame::{FramePayload, FrameType, VarScope},
    parser::parse_frame,
    serialize::{Ack, AgentDisconnect, AgentHello},
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
                        if let FramePayload::KVList(kv_pairs) = &frame.payload {
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

                        // Create the response frame
                        let frame = agent_hello.to_frame();

                        println!("Sending AgentHello: {:#?}", frame);

                        // Serialize the AgentHello into a Frame
                        match frame.serialize() {
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
                        let agent_disconnect = AgentDisconnect {
                            status_code: 0,
                            message: "Goodbye".to_string(),
                        };

                        // Create the response frame
                        let frame = agent_disconnect.to_frame();

                        println!("Sending AgentDisconnect: {:#?}", frame);

                        // Serialize the AgentDisconnect into a Frame
                        match frame.serialize() {
                            Ok(response) => {
                                socket.write_all(&response).await?;
                                socket.flush().await?;
                            }
                            Err(e) => {
                                eprintln!("Failed to serialize response: {:?}", e);
                            }
                        }

                        // Shutdown the write side of the socket
                        if let Err(e) = socket.shutdown().await {
                            eprintln!("Failed to shutdown socket: {:?}", e);
                        }
                    }

                    // Respond with Ack frame
                    FrameType::Notify => {
                        if let FramePayload::ListOfMessages(messages) = &frame.payload {
                            let mut vars = Vec::new();

                            for message in messages {
                                match message.name.as_str() {
                                    "check-client-ip" => {
                                        let random_value: u32 = rand::random_range(0..100);
                                        vars.push((
                                            VarScope::Session,
                                            "ip_score",
                                            TypedData::UInt32(random_value),
                                        ));
                                    }

                                    "log-request" => {
                                        vars.push((
                                            VarScope::Transaction,
                                            "my_var",
                                            TypedData::String("tequila".to_string()),
                                        ));
                                    }

                                    _ => {
                                        eprintln!("Unsupported message: {:?}", message.name);
                                    }
                                }
                            }

                            // Create the Ack frame
                            let ack = vars.into_iter().fold(
                                Ack::new(frame.metadata.stream_id, frame.metadata.frame_id),
                                |ack, (scope, name, value)| ack.set_var(scope, name, value),
                            );

                            // Create the response frame
                            let frame = ack.to_frame();

                            println!("Sending Ack: {:#?}", frame);

                            // Serialize the Ack into a Frame
                            match frame.serialize() {
                                Ok(response) => {
                                    socket.write_all(&response).await?;
                                    socket.flush().await?;
                                }
                                Err(e) => {
                                    eprintln!("Failed to serialize response: {:?}", e);
                                }
                            }
                        }
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
