use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use common::get_banner;
use log::info;
use std::{io::ErrorKind, mem::replace, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream},
    sync::{Mutex, MutexGuard},
};

struct LoginServerConfig {
    host: String,
    port: u16,
}
// TODO: When auth successful to login server, allow-list connection for a time period to character server for selection
// TODO: On character selection, allow-list connection for map servers.. have servers maintain allowed IPs list, to identify hacking attempts and block

// Login server packets
const LOGIN_AUTH_ATTEMPT: u16 = 0x0064;

struct AuthData {
    protocol_version: u32,
    username: String,
    password: String,
    unknown: u8,
}

type MutexStream<'a> = MutexGuard<'a, BufStream<TcpStream>>;

async fn read_login_authenticate_data(stream: &mut MutexStream<'_>) -> Result<AuthData> {
    // Padding, not sure what these represent yet
    let protocol_version = stream.read_u32_le().await.unwrap();
    let mut username = [0; 24];
    stream.read_exact(&mut username).await?;

    let mut password = [0; 24];
    stream.read_exact(&mut password).await?;

    println!("RAW LOGIN CREDENTIALS, username={username:?}, password={password:?}");

    // FIXME: Write a "read until null function"
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

    let _unknown = stream.read_u8().await.unwrap();

    Ok(AuthData {
        protocol_version,
        username,
        password,
        unknown: _unknown,
    })
}

async fn write_login_auth_error(stream: &mut MutexStream<'_>) -> Result<()> {
    // Command: 0x006a
    // FIXME: Move these reasons into enums
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
    stream.write_all(&bad_password).await?;
    stream.flush().await?;

    Ok(())
}

enum BanReason {
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

async fn write_packet(packet: &Vec<u8>, stream: &mut MutexStream<'_>) -> Result<()> {
    println!("Raw packet: len={}, body={packet:?},", packet.len());
    stream.write_all(packet).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_login_banned(stream: &mut MutexStream<'_>, reason: BanReason) -> Result<()> {
    let command: u16 = 0x0081;
    let reason: u8 = reason as u8;
    let mut packet: Vec<u8> = vec![];
    packet.append(&mut command.to_le_bytes().to_vec());
    packet.append(&mut reason.to_le_bytes().to_vec());
    write_packet(&packet, stream).await?;
    Ok(())
}

async fn write_login_authenticate_success(stream: &mut MutexStream<'_>) -> Result<()> {
    let combine_packets = true;

    let command: u16 = 0x0ac4;
    let login_packets_bytes_length: u16 = 0; // This will be computed and replaced out in later steps.
    let login_id1: u32 = 0x1d266809;
    let account_id: u32 = 0x005dbb1d;
    let login_id2: u32 = 0x00000000;
    let last_login_ip: u32 = 0x00000000; // Not used, zero
    let last_login_time: [u8; 26] = [0; 26]; // Not used, zero
    let gender: u8 = 0;
    let session_id = "TPZMgc02C0iARyrU"; // TODO: Come up with a hash for this value, and determine when it gets used
    let twitter_flag: u8 = 0;

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut command.to_le_bytes().to_vec());
    packet.append(&mut login_packets_bytes_length.to_le_bytes().to_vec());
    packet.append(&mut login_id1.to_le_bytes().to_vec());
    packet.append(&mut account_id.to_le_bytes().to_vec());
    packet.append(&mut login_id2.to_le_bytes().to_vec());
    packet.append(&mut last_login_ip.to_le_bytes().to_vec());
    packet.append(&mut last_login_time.to_vec());
    packet.append(&mut gender.to_le_bytes().to_vec());
    packet.append(&mut session_id.as_bytes().to_vec());
    packet.append(&mut twitter_flag.to_le_bytes().to_vec());

    let mut server_list_packet = get_login_character_servers_list_packet();

    // Rewrite the length portion of the packet with the compute of success+server_list packets
    let base_packet_len = packet.len() as u16;
    let total_packet_len = base_packet_len + server_list_packet.len() as u16;
    let packet_len_as_bytes = total_packet_len.to_le_bytes();
    for i in 0..=1 {
        let _ = replace(&mut packet[2 + i], packet_len_as_bytes[i]);
    }

    // FIXME: Remove the block that doesn't apply once we prove this works
    if combine_packets {
        let mut combined_packet = packet.clone();
        combined_packet.append(&mut server_list_packet);
        write_packet(&combined_packet, stream).await?;
    } else {
        write_packet(&packet, stream).await?;
        write_packet(&server_list_packet, stream).await?;
    }

    Ok(())
}

enum GeneralPopulation {
    Smooth = 0,
    Normal = 1,
    Busy = 2,
    Crowded = 3,
    Undefined = 4,
}

fn get_login_character_servers_list_packet() -> Vec<u8> {
    let ip: &[u8; 4] = &[192, 168, 1, 70];
    let port: u16 = 4500;

    let name = "Cerberus";
    let mut raw_name: [u8; 20] = [0; 20];
    for (ch_index, ch) in name.chars().enumerate() {
        raw_name[ch_index] = ch as u8;
    }

    let population: u16 = GeneralPopulation::Undefined as u16;
    let state: u16 = 0x00; // TODO: Figure out what these flags mean
    let property: u16 = 0x00; // TODO: Figure out what these properties mean
    let unknown: [u8; 128] = [0; 128];

    let mut packet: Vec<u8> = vec![];
    packet.append(&mut ip.to_vec());
    packet.append(&mut port.to_le_bytes().to_vec());
    packet.append(&mut raw_name.to_vec());
    packet.append(&mut population.to_le_bytes().to_vec());
    packet.append(&mut state.to_le_bytes().to_vec());
    packet.append(&mut property.to_le_bytes().to_vec());
    packet.append(&mut unknown.to_vec());

    packet
}

async fn handle_login_attempt(stream: &mut MutexStream<'_>) -> Result<()> {
    println!("This is a login attempt command");

    let auth_data = read_login_authenticate_data(stream).await.unwrap();
    let username = auth_data.username;
    let password = auth_data.password;

    println!("LOGIN CREDENTIALS, username={username:?}, password={password:?}");

    // Fake an invalid login error
    if password == "000failpassword" {
        println!("Returning invalid password!");
        write_login_auth_error(stream).await?;
        return Ok(());
        // return Err(anyhow!("Invalid username or password"));
    }

    if password == "000fail" {
        println!("Returning session exists");
        write_login_banned(stream, BanReason::Disconnected).await?;
        return Err(anyhow!("Session already exists"));
    }

    println!("Returning successful login and server list..");
    write_login_authenticate_success(stream).await?;

    Ok(())
}

async fn handle_command(stream: &mut MutexStream<'_>) -> Result<()> {
    // Determine the type of command being called by connected client
    let mut raw_command_type: [u8; 2] = [0; 2];
    let command_type_check = stream.read_exact(&mut raw_command_type).await;

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
        handle_login_attempt(stream).await?;
    } else {
        println!("UNHANDLED PACKET TYPE: {:?}", command_type);
        return Err(anyhow!("Unsupported packed type: {:?}", command_type));
    }

    Ok(())
}

struct Connection {
    id: usize,
    address: SocketAddr,
    stream: Arc<Mutex<BufStream<TcpStream>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // FIXME: Load host/port/configs from env vars
    let config = LoginServerConfig {
        host: "0.0.0.0".to_string(),
        port: 6900,
    };
    let host_port = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&host_port).await?;

    let all_connections: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(vec![]));

    info!("");
    for line in get_banner() {
        info!("{line}");
    }
    info!("");
    info!("Login server started on {}:{}..", config.host, config.port);

    // Connect new streams
    let mut latest_connection_id: usize = 0;
    loop {
        let (raw_stream, address) = listener.accept().await.unwrap();
        latest_connection_id += 1;
        raw_stream.set_nodelay(true).unwrap();

        info!("{address} connected");

        let original_stream = Arc::new(Mutex::new(BufStream::new(raw_stream)));

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

            loop {
                let mut stream = stream.lock().await;
                let result = handle_command(&mut stream).await;

                if result.is_err() {
                    break;
                }
            }

            // Disconnect and remove from connections list
            connections.lock().await.retain(|c| c.id != connection_id);
            info!("{address} disconnected");
        });
    }
}
