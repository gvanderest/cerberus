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
    protocol_version: u32,
    username: String,
    password: String,
    unknown: u8,
}

type Stream = BufStream<TcpStream>;

fn read_login_authenticate_data(stream: &mut Stream) -> Result<LoginAuthenticateData> {
    // Padding, not sure what these represent yet
    let mut raw_protocol_version: [u8; 4] = [0; 4];
    stream.read_exact(&mut raw_protocol_version)?;
    let protocol_version = u32::from_le_bytes(raw_protocol_version);

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

    let mut raw_unknown: [u8; 1] = [0; 1];
    stream.read_exact(&mut raw_unknown)?;

    Ok(LoginAuthenticateData {
        protocol_version,
        username,
        password,
        unknown: raw_unknown[0],
    })
}

fn write_login_invalid_login_error(stream: &mut Stream) -> Result<()> {
    // 0x01 - Invalid username and password.
    // 0x02 - This ID is expired.
    // 0x03 - Rejected from server.
    // 0x04 - Account ID blocked by the Game Master Team
    // 0x05 - Your Game's Exe File is not the latest version
    // 0x06 - You are prohibited to log in until XX. (not sure how to provide date)
    // 0x07 - Server is jammed due to overpopulation.  Please try again after few minutes.
    // 0x08 - This account can't connext the Sakray server.
    // 0x09 - MSI_REFUSE_BAN_BY_DBA
    // 0x10 - A korean un-translated message, relates to "password change agreement" URL
    // 0x11 - This account has been used for illegal program of hacking program.. Block Time: XX.
    // 0x12 - The possibility of exposure to illegal program, PC virus infection, or Hacking Tool has been detected.
    // 0x13 - OTP password is 6 digits long
    // 0x14 - OTP information is unavailable.
    // 0x15 - Failed to recognize SSO
    // 0x16 - Your connection is currently delayed. Please reconnect again later.
    // 0x17 to 0x20 - same as 0x16
    // 0x20 - Rejected from Server (32)
    // 0x21 - only otp user login allow
    // 0x22 - Rejected from Server (34)
    // 0x23 - Rejected from Server (35)
    // 0x24 - This account has limited in-game access due to a secondary password mis-input.
    // 0x25 onward - Rejected from Server (offset + 12 in parens)
    let reason: u8 = 0x01;
    let bad_password: [u8; 23] = [
        0x6a, 0x00, reason, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // let bad_password: [u8; 30] = [
    //     0xe0, 0x0a, 0x54, 0x14, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d,
    //     0x00, 0x00, 0x2d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ];
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
    // let command: u16 = 0x0a4d;
    let command: u16 = 0x0069;
    // let command: u16 = 0x0276;
    // Packets length is .. this packet size of 47 + 32 * server count
    let login_packets_bytes_length: u16 = 47 + (32 * 1);
    // let login_packets_bytes_length: u16 = 47 + (32 * 1);
    let login_id1: u32 = 0x1d266809;
    let account_id: u32 = 0x005dbb1d;
    let login_id2: u32 = 0x00000000;
    let lastlogin_ip: u32 = 0x00000000;
    let unknown_bytes: [u8; 26] = [0; 26];
    let gender: u8 = 0;

    // let mut raw_mnemonic: [u8; 16] = [0; 16];
    // for (ch_index, ch) in "TPZMgc02COiARyrU".chars().enumerate() {
    //     raw_mnemonic[ch_index] = ch as u8;
    // }

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut command.to_le_bytes().to_vec());
    packet.append(&mut login_packets_bytes_length.to_le_bytes().to_vec());
    packet.append(&mut login_id1.to_le_bytes().to_vec());
    packet.append(&mut account_id.to_le_bytes().to_vec());
    packet.append(&mut login_id2.to_le_bytes().to_vec());
    packet.append(&mut lastlogin_ip.to_le_bytes().to_vec());
    packet.append(&mut unknown_bytes.to_vec());
    // packet.append(&mut raw_mnemonic.to_vec());
    packet.append(&mut gender.to_le_bytes().to_vec());

    println!("Raw packet: len={}, body={packet:?},", packet.len());

    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(())
}

fn write_login_character_servers_list(stream: &mut Stream) -> Result<()> {
    let ip: &[u8; 4] = &[192, 168, 1, 70];
    let port: u16 = 4501;
    let population: u16 = 1557;

    let name = "Cerberus";
    let mut raw_name: [u8; 20] = [0; 20];
    for (ch_index, ch) in name.chars().enumerate() {
        raw_name[ch_index] = ch as u8;
    }

    let padding_suffix: [u8; 4] = [0; 4];

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut ip.to_vec());
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
            return Ok(());
            // return Err(anyhow!("Invalid username or password"));
        }

        if password == "000fail" {
            println!("Returning session exists");
            write_login_disconnect(stream, DisconnectReason::Disconnected)?;
            return Err(anyhow!("Session already exists"));
        }

        println!("Returning successful login..");
        write_login_authenticate_success(stream)?;

        println!("Returning a server list..");
        write_login_character_servers_list(stream)?;
    } else {
        println!("UNHANDLED PACKET TYPE: {:?}", command_type);
        return Err(anyhow!("Unsupported packed type: {:?}", command_type));
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
