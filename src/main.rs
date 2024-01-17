use anyhow::{anyhow, Result};
use bufstream::BufStream;
use byteorder::{ByteOrder, LittleEndian};
use std::{
    io::{prelude::*, ErrorKind},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, sleep},
    time::Duration,
};

struct LoginServerConfig {
    host: String,
    port: u16,
}
// TODO: Spin up character server
// TODO: When auth successful to login server, allow-list connection for a time period to character server for selection
// TODO: On character selection, allow-list connection for map servers.. have servers maintain allowed IPs list, to identify hacking attempts and block

// Login server packets
const LOGIN_AUTH_ATTEMPT: u16 = 0x0064;

struct LoginAuthenticateData {
    unknown_1: u32,
    username: String,
    password: String,
    unknown_2: u8,
}

type Stream = BufStream<TcpStream>;

fn read_login_authenticate_data(stream: &mut Stream) -> Result<LoginAuthenticateData> {
    // Padding, not sure what these represent yet
    let mut raw_unknown_1: [u8; 4] = [0; 4];
    stream.read_exact(&mut raw_unknown_1)?;
    let unknown_1 = u32::from_le_bytes(raw_unknown_1);

    let mut username = [0; 24];
    stream.read_exact(&mut username)?;

    let mut password = [0; 24];
    stream.read_exact(&mut password)?;

    println!("RAW LOGIN CREDENTIALS, username={username:?}, password={password:?}");

    let username_index_of_null = username.iter().enumerate().find(|(_index, c)| **c == 0);
    let username = String::from_utf8(
        username
            .to_vec()
            .iter()
            .take(match username_index_of_null {
                Some((index, _char)) => index,
                _ => username.len(),
            })
            .copied()
            .collect(),
    )
    .unwrap();

    let password_index_of_null = password.iter().enumerate().find(|(_index, c)| **c == 0);
    let password = String::from_utf8(
        password
            .to_vec()
            .iter()
            .take(match password_index_of_null {
                Some((index, _char)) => index,
                _ => password.len(),
            })
            .copied()
            .collect(),
    )
    .unwrap();

    let mut raw_unknown_2: [u8; 1] = [0; 1];
    stream.read_exact(&mut raw_unknown_2)?;

    Ok(LoginAuthenticateData {
        unknown_1,
        username,
        password,
        unknown_2: raw_unknown_2[0],
    })
}

fn write_login_invalid_login_error(stream: &mut Stream) -> Result<()> {
    let bad_password: [u8; 30] = [
        0xe0, 0x0a, 0x54, 0x14, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d,
        0x00, 0x00, 0x2d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&bad_password)?;
    stream.flush().unwrap();

    Ok(())
}

enum DisconnectReason {
    Disconnected = 0,
    ServerClosed = 1,
    SessionTakenOver = 2,
    TimeoutReached = 3,
    ServerJammedRetrySoon = 4,
    AgeLimit = 5, // "Age Limit from Commandment Tables"
    IdUnpaid = 6,
    ServerJammedRetryLater = 7,
    SessionExists = 8,
    IpCapacityForCafeFull = 9,
    SubscriptionEnded = 10,
    AccountSuspended = 11,
    ChangeInBillingPolicy = 12,
    AuthorizedIpMismatch = 13,
    PreventChargingPlayTime = 14,
    // 15 is same as 0
    NotAvailable = 16,
    // 17 is same as 16
    AccountalreadyConnected = 18,
    // 19+ is all "Disconnected"
}

fn write_login_disconnect(stream: &mut Stream, reason: DisconnectReason) -> Result<()> {
    let command: u16 = 0x0081;
    let reason: u8 = 26 as u8;
    let mut packet: Vec<u8> = vec![];
    packet.append(&mut command.to_le_bytes().to_vec());
    packet.append(&mut reason.to_le_bytes().to_vec());
    stream.write_all(&packet)?;
    stream.flush().unwrap();

    Ok(())
}

fn write_login_authenticate_success(stream: &mut Stream) -> Result<()> {
    let login_success_command: u16 = 0x0a4d;
    let weird_bytes: u16 = 0x00a0;
    let login_id1: u32 = 123456;
    let account_id: u32 = 55555;
    let login_id2: u32 = 0;
    let unknown_bytes: [u8; 31] = [0; 31];

    let mut raw_mnemonic: [u8; 16] = [0; 16];
    // for (ch_index, ch) in "TPZMgc02COiARyrU".chars().enumerate() {
    for (ch_index, ch) in "0RUMcyi2rgTPOCAZ".chars().enumerate() {
        raw_mnemonic[ch_index] = ch as u8;
    }
    let gender: u8 = 0;

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut login_success_command.to_le_bytes().to_vec());
    packet.append(&mut weird_bytes.to_le_bytes().to_vec());
    packet.append(&mut login_id1.to_le_bytes().to_vec());
    packet.append(&mut account_id.to_le_bytes().to_vec());
    packet.append(&mut login_id2.to_le_bytes().to_vec());
    packet.append(&mut unknown_bytes.to_vec());
    packet.append(&mut raw_mnemonic.to_vec());
    packet.append(&mut gender.to_le_bytes().to_vec());

    println!("Raw packet: len={}, body={packet:?},", packet.len());

    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(())
}

fn write_login_character_servers_list(stream: &mut Stream) -> Result<()> {
    let server_list_command_prefix: u16 = 0xf180;
    let population: u16 = 123;
    let ip_suffix: &[u8; 2] = &[1, 70];
    let port: u16 = 4501;

    let name = "Cerberus";
    let mut raw_name: [u8; 20] = [0; 20];
    for (ch_index, ch) in name.chars().enumerate() {
        raw_name[ch_index] = ch as u8;
    }

    let padding_suffix: [u8; 4] = [0; 4];

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut server_list_command_prefix.to_le_bytes().to_vec());
    packet.append(&mut ip_suffix.to_vec());
    packet.append(&mut port.to_le_bytes().to_vec());
    packet.append(&mut raw_name.to_vec());
    packet.append(&mut population.to_le_bytes().to_vec());
    packet.append(&mut padding_suffix.to_vec());

    println!("Raw packet: len={}, body={packet:?},", packet.len());

    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(())
}

fn handle_login_stream(stream: &mut Stream) -> Result<()> {
    // Determine the type of command being called by connected client
    let mut raw_command_type: [u8; 2] = [0; 2];
    let command_type_check = stream.read_exact(&mut raw_command_type);

    if let Err(err) = command_type_check {
        if err.kind() == ErrorKind::WouldBlock {
            // Blocking port, not an issue, but nothing to do
            return Ok(());
        } else {
            return Err(anyhow!("Connection lost"));
        }
    }

    let command_type = LittleEndian::read_u16(&raw_command_type);
    println!("COMMAND TYPE: 0x{command_type:04x}");

    // FIXME: Make a function that maps command prefix to an enum or structs

    // Handle the command from the client
    if command_type == LOGIN_AUTH_ATTEMPT {
        println!("This is a login attempt command");

        let auth_data = read_login_authenticate_data(stream)?;
        let username = auth_data.username;
        let password = auth_data.password;

        println!("LOGIN CREDENTIALS, username={username:?}, password={password:?}");

        // Fake an invalid login error
        if password == "000failpassword" {
            println!("Returning invalid password!");
            write_login_invalid_login_error(stream)?;
            return Err(anyhow!("Invalid username or password"));
        }

        if password == "000fail" {
            println!("Returning session exists");
            write_login_disconnect(stream, DisconnectReason::SessionExists)?;
            return Err(anyhow!("Session already exists"));
        }

        println!("Returning successful login..");
        write_login_authenticate_success(stream)?;

        println!("Returning a server list..");
        write_login_character_servers_list(stream)?;
    } else {
        println!("UNHANDLED PACKET TYPE: {:?}", command_type);
        // FIXME: Pass up an error
        return Ok(());
    }

    Ok(())
}

struct Connection {
    id: usize,
    stream: Stream,
    should_drop: bool,
}

fn main() -> Result<()> {
    // FIXME: Load host/port/configs from env vars
    let config = LoginServerConfig {
        host: "0.0.0.0".to_string(),
        port: 6900,
    };
    let host_port = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&host_port)?;

    let connections: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(vec![]));

    println!("Server up and running at {host_port}..");

    // Handle all streams
    let connections_ref = Arc::clone(&connections);
    thread::spawn(move || loop {
        for connection in connections_ref.lock().unwrap().iter_mut() {
            let result = handle_login_stream(&mut connection.stream);
            if result.is_err() {
                // Mark connection for removal
                println!("Removing connection {}", connection.id);
                connection.should_drop = true;
            }
        }

        // Drop all connections marked for removal
        connections_ref.lock().unwrap().retain(|c| !c.should_drop);

        sleep(Duration::from_millis(10));
    });

    // Connect new streams
    for (connection_id, stream) in listener.incoming().enumerate() {
        let stream = stream.unwrap();
        stream.set_nodelay(true).unwrap();
        stream.set_nonblocking(true).unwrap();
        let stream = BufStream::new(stream);

        let streams = Arc::new(&connections);
        let peer_address = stream.get_ref().peer_addr().unwrap();
        let connection = Connection {
            id: connection_id,
            stream,
            should_drop: false,
        };
        println!(
            "Added connection {} from IP {}",
            connection.id,
            peer_address.ip()
        );
        streams.lock().unwrap().push(connection);
    }

    Ok(())
}
