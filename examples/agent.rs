use anyhow::Result;
use bytes::BytesMut;
use spop::parser::parse_frame; // Adjust according to your library structure
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

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

        match parse_frame(&buffer) {
            Ok(frame) => {
                println!("Received frame: {:?}", frame);
                respond_ok(&mut socket).await?;
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
