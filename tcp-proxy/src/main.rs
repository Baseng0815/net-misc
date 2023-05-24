use std::env;
use std::net::{TcpListener};


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

    let listener = TcpListener::bind(src).unwrap();

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            println!("Accepted incoming connection by peer {:?}", stream.peer_addr().unwrap());
        }
    }
}
