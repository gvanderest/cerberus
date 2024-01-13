use std::{
    io::{prelude::*, BufReader},
    net::TcpListener,
};

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

    // accept connections and process them serially
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mut reader = BufReader::new(&stream);
        println!("GOT A NEW CONNECTION!!");

        let mut packet_type: [u8; 6] = [0; 6];

        loop {
            let packet_type_check = reader.read_exact(&mut packet_type);

            if packet_type_check.is_ok() {
                println!("PACKET TYPE: {packet_type:?}");
                if packet_type == [100, 0, 55, 0, 0, 0] {
                    let mut username = [0; 24];
                    reader.read_exact(&mut username)?;

                    let mut password = [0; 24];
                    reader.read_exact(&mut password)?;

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

                    println!("LOGIN CREDENTIALS, username={username:?}, password={password:?}");
                } else {
                    println!("UNHANDLED PACKET TYPE: {:?}", packet_type);
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
