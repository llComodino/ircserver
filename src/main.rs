extern crate openssl;
extern crate tokio;

use std::env;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use openssl::symm::{Cipher, Crypter, Mode};
use tokio::net::TcpListener;
use tokio::prelude::*;

struct Client {
    username: String,
    addr: SocketAddr,
    encrypter: Crypter,
    decrypter: Crypter,
}

struct Server {
    clients: Mutex<Vec<Client>>,
}

impl Server {
    fn new() -> Self {
        Server {
            clients: Mutex::new(Vec::new()),
        }
    }

    fn broadcast(&self, message: &[u8]) {
        let clients = self.clients.lock().unwrap();
        for client in clients.iter() {
            let mut encrypter = client.encrypter.clone();
            encrypter.update(message, &mut Vec::new()).unwrap();
            let encrypted_message = encrypter.finalize().unwrap();
            client.addr.send(encrypted_message);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_key = env::var("SERVER_KEY")?;
    let server_iv = env::var("SERVER_IV")?;
    let server_port = env::var("SERVER_PORT")?;

    let server_key = server_key.as_bytes();
    let server_iv = server_iv.as_bytes();
    let server_port: u16 = server_port.parse()?;
    
    let server_addr = format!("0.0.0.0:{}", server_port);
    let server_addr: SocketAddr = server_addr.parse()?;

    let listener = TcpListener::bind(&server_addr)?;
    let server = Arc::new(Server::new());

    println!("Listening for connections on {}", server_addr);

    let server_clone = server.clone();
    tokio::spawn(listener.incoming().for_each(move |socket| {
        let (reader, writer) = socket.split();
        let addr = socket.peer_addr().unwrap();

        let server = server_clone.clone();
        let (username, encrypter, decrypter) = match get_client_info(reader) {
            Ok((username, encrypter, decrypter)) => (username, encrypter, decrypter),
            Err(_) => {
                let msg = b"Invalid client info\n";
                addr.send(msg);
                return Ok(());
            }
        };
        ok(())
    }));

        println!("New client connected: {} ({})", username, addr);
        server.clients.lock().unwrap().push(Client {
            username,
            addr,
            encrypter,
            decrypter
        });

    let (input_tx, input_rx) = tokio::sync::mpsc::channel(1024);
    let server_clone = server.clone();
    tokio::spawn(input_rx.for_each(move |(username, message)| {
        println!("{}: {}", username, String::from_utf8_lossy(&message));
        let mut clients = server_clone.clients.lock().unwrap();
        let client = clients.iter_mut().find(|client| client.username == username).unwrap();
        client.addr.send(&message);
        Ok(())
    }));

    let mut client_input = String::new();
    while client_input != ":q" {
        std::io::stdin().read_line(&mut client_input)?;
        let username = "Server";
        let message = client_input.trim().as_bytes();
        input_tx.try_send((username.to_string(), message.to_vec()))?;
        client_input.clear();
    }
    Ok(())
}

fn get_client_info<T:AsyncRead + AsyncWrite>(
    stream: T,
) -> Result<(String, Crypter, Crypter), Box<dyn std::error::Error>> {
    let mut buf = [0; 1024];

    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Err(Error::new(ErrorKind::ConnectionAborted, "Connection Closed"));
    }

    let mut decrypter = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Decrypt,
        &env::var("SERVER_KEY")?,
        Some(&env::var("SERVER_IV")?),
    )?;
    let mut decrypted = Vec::new();
    decrypter.update(&buf[..n], &mut decrypted)?;
    decrypted.extend_from_slice(decrypter.finalize(&mut decrypted)?.as_slice());

    let mut words = decrypted.split(|b| *b == b' ');
    let username = match words.next() {
        Some(word) => String::from_utf8(word.to_vec())?,
        None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid client info")),
    };

    let key = match words.next() {
        Some(word) => word,
        None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid client info")),
    };

    let iv = match words.next() {
        Some(word) => word,
        None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid client info")),
    };

    let mut encrypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(iv))?;
    let mut decrypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, key, Some(iv))?;

    Ok((username, encrypter, decrypter))
}
