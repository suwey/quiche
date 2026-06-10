//! UoT probe — sends a single hardcoded DNS A query for `example.com` over
//! the anytls outbound named by <tag>, prints the first response (or times
//! out after 5s), then exits.
//!
//! Usage:
//!   cargo run -p anywhere --bin uot_probe -- <config.toml> <tag> <dest>
//!
//! Example:
//!   RUST_LOG=debug cargo run -p anywhere --bin uot_probe --
//! ~/anytls-client.toml proxy 8.8.8.8:53

use std::time::Duration;

use anywhere::config::Config;
use anywhere::inbound::Destination;
use anywhere::outbound::registry::OutboundRegistry;

/// Minimal DNS A query for `example.com`, transaction id 0xABCD.
fn dns_query_example_com() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0xAB, 0xCD]); // ID
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
    // QNAME: example.com
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00); // root
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut args = std::env::args().skip(1);
    let config_path = args.next().ok_or("missing <config.toml>")?;
    let tag = args.next().ok_or("missing <tag>")?;
    let dest_str = args.next().ok_or("missing <dest>")?;

    let dest: Destination = dest_str.parse()?;
    println!("loading config from {config_path}");
    let config = Config::load(&config_path)?;
    let registry = OutboundRegistry::from_config(&config).await?;
    let client = registry
        .get(&tag)
        .ok_or_else(|| format!("no outbound tag '{tag}'"))?;

    println!("dial_udp via tag={tag} dest={dest}");
    let mut packet = client.dial_udp(&dest).await?;

    let query = dns_query_example_com();
    println!("sending {} byte DNS query", query.len());
    packet.write_packet(&query, &dest).await?;

    let mut buf = vec![0u8; 4096];
    let recv = tokio::time::timeout(
        Duration::from_secs(5),
        packet.read_packet(&mut buf),
    )
    .await;

    match recv {
        Ok(Ok((n, from))) => {
            println!("got {n} bytes from {from}");
            let head = n.min(64);
            print!("hex:");
            for b in &buf[..head] {
                print!(" {b:02x}");
            }
            println!();
            if n == 0 {
                eprintln!("warning: 0-byte read (EOF from stream)");
            }
        },
        Ok(Err(e)) => {
            eprintln!("read_packet error: {e}");
            return Err(e.into());
        },
        Err(_) => {
            eprintln!("timeout waiting for response");
            return Err("timeout".into());
        },
    }

    Ok(())
}
