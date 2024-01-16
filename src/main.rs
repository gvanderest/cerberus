use bufstream::BufStream;
use byteorder::{ByteOrder, LittleEndian};
use std::{
    io::prelude::*,
    net::{Shutdown, TcpListener},
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

fn main() -> std::io::Result<()> {
    let config = LoginServerConfig {
        host: "0.0.0.0".to_string(),
        port: 6900,
    };
    let host_port = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&host_port)?;

    println!("Server up and running at {host_port}..");

    // accept connections and process them serially
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut stream = BufStream::new(&mut stream);
        println!("GOT A NEW CONNECTION!!");

        let return_bad_password = false;

        loop {
            // Read the packet type
            let mut raw_command_type: [u8; 2] = [0; 2];
            let command_type_check = stream.read_exact(&mut raw_command_type);

            if command_type_check.is_ok() {
                let command_type = LittleEndian::read_u16(&raw_command_type);
                println!("COMMAND TYPE: 0x{command_type:04x}");

                if command_type == LOGIN_AUTH_ATTEMPT {
                    println!("This is a login attempt command");
                    // Padding, not sure what these represent yet
                    let mut padding: [u8; 4] = [0; 4];
                    stream.read_exact(&mut padding)?;

                    let mut username = [0; 24];
                    stream.read_exact(&mut username)?;

                    let mut password = [0; 24];
                    stream.read_exact(&mut password)?;

                    println!("RAW LOGIN CREDENTIALS, username={username:?}, password={password:?}");

                    let username_index_of_null =
                        username.iter().enumerate().find(|(_index, c)| **c == 0);
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

                    let password_index_of_null =
                        password.iter().enumerate().find(|(_index, c)| **c == 0);
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

                    // Gender? 0x00 for male, 0x01 for female?
                    let mut gender: [u8; 1] = [0; 1];
                    stream.read_exact(&mut gender)?;

                    println!("LOGIN CREDENTIALS, username={username:?}, password={password:?}");

                    // Fake an invalid login error
                    if return_bad_password {
                        println!("Returning invalid password!");
                        let bad_password: [u8; 30] = [
                            0xe0, 0x0a, 0x54, 0x14, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x2d, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x3a,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ];
                        stream.write_all(&bad_password)?;
                        stream.flush().unwrap();
                        continue;
                    } else {
                        println!("Returning successful login..");
                        let login_success_command: u16 = 0x0a4d;
                        let weird_bytes: u16 = 0x00a0;
                        let login_id1: u32 = 123456;
                        let account_id: u32 = 55555;
                        let login_id2: u32 = 0;
                        let unknown_bytes: [u8; 31] = [0; 31];

                        let mut raw_mnemonic: [u8; 16] = [0; 16];
                        for (ch_index, ch) in "TPZMgc02COiARyrU".chars().enumerate() {
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

                        stream.flush()?;

                        println!("Returning a server list..");
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
                        stream.write_all(&packet)?;
                        stream.write_all(&packet)?;

                        stream.flush()?;
                    }
                } else {
                    println!("UNHANDLED PACKET TYPE: {:?}", command_type);
                    break;
                }
            } else {
                println!("Connection lost!");
                break;
            }
        }
    }
    Ok(())
}
