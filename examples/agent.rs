use anyhow::Result;
use bytes::BytesMut;
use spop::{
    SpopFrame, SpopFrameExt,
    actions::VarScope,
    frame::{FramePayload, FrameType},
    frames::{Ack, AgentDisconnect, AgentHello, HaproxyHello},
    parser::parse_frame,
    types::TypedData,
};
use std::path::Path;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[tokio::main]
async fn main() -> Result<()> {
    // to use TCP, uncomment the following lines, and add
    // net::{TcpListener, TcpStream}
    //
    // let listener = TcpListener::bind("0.0.0.0:12345").await?;
    // println!("SPOE Agent listening on port 12345...");
    //
    // loop {
    //     let (socket, addr) = listener.accept().await?;
    //     println!("New connection from {}", addr);
    //     tokio::spawn(handle_connection(socket));
    // }

    let socket_path = "spoa_agent/spoa.sock";

    // Clean up the socket if it already exists
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    #[cfg(unix)]
    {
        // Set permissions to 777 (testing purposes)
        let perms = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(socket_path, perms)?;
    }

    println!("SPOE Agent listening on UNIX socket at {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                println!("New UNIX connection from {:?}", stream);
                tokio::spawn(handle_connection(stream));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {:?}", e);
            }
        }
    }
}

async fn handle_connection(mut socket: UnixStream) -> Result<()> {
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

                match frame.frame_type() {
                    // Respond with AgentHello frame
                    FrameType::HaproxyHello => {
                        let hello = HaproxyHello::try_from(frame.payload())
                            .map_err(|_| anyhow::anyhow!("Failed to parse HaproxyHello"))?;

                        let max_frame_size = hello.max_frame_size;
                        let is_healthcheck = hello.healthcheck.unwrap_or(false);
                        // * "version"    <STRING>
                        // This is the SPOP version the agent supports. It must follow the format
                        // "Major.Minor" and it must be lower or equal than one of major versions
                        // announced by HAProxy.
                        let version = "2.0".to_string();

                        // Create the AgentHello with the values
                        let agent_hello = AgentHello {
                            version,
                            max_frame_size,
                            capabilities: vec![], // Empty capabilities for now
                        };

                        println!("Sending AgentHello: {:#?}", agent_hello.payload());

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

                        if is_healthcheck {
                            // Shutdown the write side of the socket
                            if let Err(e) = socket.shutdown().await {
                                eprintln!("Failed to shutdown socket: {:?}", e);
                            }
                        }
                    }

                    // Respond with AgentDisconnect frame
                    FrameType::HaproxyDisconnect => {
                        let agent_disconnect = AgentDisconnect {
                            status_code: 0,
                            message: "Goodbye".to_string(),
                        };

                        println!("Sending AgentDisconnect: {:#?}", agent_disconnect.payload());

                        // Serialize the AgentDisconnect into a Frame
                        match agent_disconnect.serialize() {
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
                        if let FramePayload::ListOfMessages(messages) = &frame.payload() {
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
                                Ack::new(frame.metadata().stream_id, frame.metadata().frame_id),
                                |ack, (scope, name, value)| ack.set_var(scope, name, value),
                            );

                            // Create the response frame
                            println!("Sending Ack: {:#?}", frame.payload());

                            // Serialize the Ack into a Frame
                            match ack.serialize() {
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
                        eprintln!("Unsupported frame type: {:?}", frame.frame_type());
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
