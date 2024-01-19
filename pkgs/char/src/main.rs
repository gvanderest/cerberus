use common::get_banner;
use log::{info, warn};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, BufStream},
    net::{TcpListener, TcpStream},
    sync::{Mutex, MutexGuard},
};

struct Connection {
    id: usize,
    address: SocketAddr,
    stream: Arc<Mutex<BufStream<TcpStream>>>,
}

#[derive(Debug)]
enum Gender {
    Male = 0,
    Female = 1,
}

#[derive(Debug)]
struct AuthData {
    account_id: u32,
    login_id1: u32,
    login_id2: u32,
    gender: Gender,
}

#[derive(Debug)]
enum CharCommand {
    Auth(u16, AuthData),
    Unknown(u16, Vec<u8>),
    Disconnected,
}

const AUTH_COMMAND: u16 = 0x0065;

type MutexStream<'a> = MutexGuard<'a, BufStream<TcpStream>>;

fn gender_from_u8(gender: u8) -> Gender {
    match gender {
        1 => Gender::Female,
        _ => Gender::Male,
    }
}

async fn parse_auth_command(stream: &mut MutexStream<'_>) -> AuthData {
    let account_id = stream.read_u32_le().await.unwrap();
    let login_id1 = stream.read_u32_le().await.unwrap();
    let login_id2 = stream.read_u32_le().await.unwrap();
    let _unknown = stream.read_u16_le().await.unwrap();
    let gender = stream.read_u8().await.unwrap();

    AuthData {
        account_id,
        login_id1,
        login_id2,
        gender: gender_from_u8(gender),
    }
}

async fn parse_incoming_command(stream: &mut MutexStream<'_>) -> CharCommand {
    let mut raw_command: [u8; 2] = [0; 2];
    stream.read_exact(&mut raw_command).await.unwrap();
    let command = u16::from_le_bytes(raw_command);

    match command {
        AUTH_COMMAND => CharCommand::Auth(command, parse_auth_command(stream).await),
        _ => {
            // Read everything, then return
            let mut all_data = vec![];
            stream.read_to_end(&mut all_data).await.unwrap();
            CharCommand::Unknown(command, all_data)
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    // FIXME: Use env vars
    let ip = "0.0.0.0";
    let port = 4500;

    info!("");
    for line in get_banner() {
        info!("{line}");
    }
    info!("");
    info!("Character server started on {ip}:{port}..");

    let all_connections: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(vec![]));

    let listener = TcpListener::bind(format!("{ip}:{port}")).await?;

    // Iterate over all connections and lock them to do something..
    let connections = all_connections.clone();
    tokio::spawn(async move {
        loop {
            let count = connections.lock().await.len();
            info!("{count} connections..");
            tokio::time::sleep(Duration::from_millis(1_000)).await;
        }
    });

    // Gather connections
    let mut latest_connection_id: usize = 0;
    loop {
        let (raw_stream, address) = listener.accept().await?;
        raw_stream.set_nodelay(true).unwrap();

        let original_stream = Arc::new(Mutex::new(BufStream::new(raw_stream)));

        latest_connection_id += 1;

        let connections = all_connections.clone();
        let stream = original_stream.clone();

        tokio::spawn(async move {
            // Add to the list of connections
            let connection_id = latest_connection_id;
            connections.lock().await.push(Connection {
                id: connection_id,
                address,
                stream: stream.clone(),
            });
            info!("{address} connected");

            // Handle the commands coming from the stream
            loop {
                let mut stream = stream.lock().await;
                let result = parse_incoming_command(&mut stream).await;
                match result {
                    CharCommand::Disconnected => {
                        warn!("Socket disconnected!");
                        break;
                    }
                    CharCommand::Unknown(command, data) => {
                        warn!("Unhandled command: 0x{command:04x}: {data:?}");
                        continue;
                    }
                    _ => {
                        info!("Happy command! {result:?}");
                        continue;
                    }
                }
            }

            // Disconnect and remove from connections list
            connections.lock().await.retain(|c| c.id != connection_id);
            info!("{address} disconnected");
        });
    }
}
