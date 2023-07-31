use std::env;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: tcp-proxy <src-ip:src-port> <dst-ip:dst-port>");
        std::process::exit(1);
    }

    let src = &args[1];
    let dst = &args[2];

    println!("Setting up proxy listener on {} and forwarding incoming packages to {}...",
             src, dst);

    println!("Listening for incoming connections...");
    let listener = TcpListener::bind(src).unwrap();
    let connection_src = listener.accept().unwrap();
    println!("Accepted incoming connection by peer {:?}", connection_src.1);
    let mut connection_src = connection_src.0;

    println!("Establishing connection to destination {}...", dst);
    let mut connection_dst = TcpStream::connect(dst).unwrap();
    println!("Connection established. Data will be proxied now");

    // src -> proxy -> dst
    let t1 = thread::spawn(|| {
        loop {
            let mut buf = [0u8; 256];
            let bytes_read = connection_src.read(&mut buf[..]).unwrap_or(0);
            if bytes_read == 0 {
                continue;
            }

            println!("Received {} bytes from src, sending to dst...", bytes_read);
            connection_dst.write(&buf[..bytes_read]);
        }
    });

    // src <- proxy <- dst
    let t2 = thread::spawn(|| {
        loop {
            let mut buf = [0u8; 256];
            let bytes_read = connection_dst.read(&mut buf[..]).unwrap_or(0);
            if bytes_read == 0 {
                continue;
            }

            println!("Received {} bytes from dst, sending to src...", bytes_read);
            connection_src.write(&buf[..bytes_read]);
        }
    });

    t1.join();
    t2.join();
}
