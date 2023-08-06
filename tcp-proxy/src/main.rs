use std::env;
use std::thread;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle_direction(src: &TcpStream, dst: &TcpStream, on_recv: fn(&[u8], usize) -> &[u8]) -> thread::JoinHandle<()> {
    let mut src = src.try_clone().unwrap();
    let mut dst = dst.try_clone().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let n = src.read(&mut buf).unwrap();
            if n == 0 {
                continue;
            }
            let res = on_recv(&buf, n);
            dst.write(&res).unwrap();
        }
    })
}

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
    let (stream_src, sockaddr_src) = listener.accept().unwrap();
    println!("Accepted incoming connection by peer {:?}", sockaddr_src);

    println!("Trying to connect to destination {:?}...", dst);
    let stream_dst = TcpStream::connect(dst).unwrap();

    let t1 = handle_direction(&stream_src, &stream_dst, |buf, n| {
        let b = &buf[..n];
        if let Ok(s) = std::str::from_utf8(b) {
            println!("{:?}", s);
        } else {
            println!("{:02x?}", b);
        }

        b
    });

    let t2 = handle_direction(&stream_dst, &stream_src, |buf, n| {
        let b = &buf[..n];
        if let Ok(s) = std::str::from_utf8(b) {
            println!("{:?}", s);
        } else {
            println!("{:02x?}", b);
        }

        b
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
