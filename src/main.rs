use std::net::{TcpListener, TcpStream};

struct Config {
    host: String,
    port: u16,
}

fn main() -> std::io::Result<()> {
    let config = Config {
        host: "0.0.0.0".to_string(),
        port: 6900,
    };
    let host_port = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&host_port)?;

    println!("Server up and running at {host_port}..");

    let mut streams = vec![];

    // accept connections and process them serially
    for stream in listener.incoming() {
        streams.push(stream);
        println!("GOT A NEW CONNECTION!!");
    }
    Ok(())
}
