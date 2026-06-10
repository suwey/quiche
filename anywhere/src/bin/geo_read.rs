//! geo_read — parse and display the contents of an SRS v2 binary rule-set file.
//!
//! Usage:
//!   cargo run -p anywhere --bin geo_read -- <path/to/file.srs>
//!
//! Example:
//!   cargo run -p anywhere --bin geo_read --
//! ~/.cache/anywhere/rule_set/geosite_geolocation-cn.srs

use std::process;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: geo_read <path/to/file.srs>");
        process::exit(1);
    });

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            process::exit(1);
        },
    };

    let parsed = match anywhere::rules::read_srs_bytes(&data) {
        Some(p) => p,
        None => {
            eprintln!("Failed to parse SRS file (not a valid SRS v2 binary)");
            process::exit(1);
        },
    };

    let flat = parsed.dump();

    println!("SRS file: {path}");
    println!();
    println!("domains ({}):", flat.domains.len());
    for d in &flat.domains {
        println!("  {d}");
    }

    println!();
    println!("domain_suffixes ({}):", flat.domain_suffixes.len());
    for d in &flat.domain_suffixes {
        println!("  .{d}");
    }

    println!();
    println!("keywords ({}):", parsed.keywords.len());
    for k in &parsed.keywords {
        println!("  \"{k}\"");
    }

    println!();
    println!("ip_ranges ({}):", parsed.ip_ranges.len());
    for r in &parsed.ip_ranges {
        let from = u128_to_ip_string(r.from);
        let to = u128_to_ip_string(r.to);
        println!("  {from} - {to}");
    }
}

fn u128_to_ip_string(val: u128) -> String {
    if val >> 32 == 0 {
        // IPv4-mapped: lower 32 bits
        let octets = val.to_be_bytes();
        format!(
            "{}.{}.{}.{}",
            octets[12], octets[13], octets[14], octets[15]
        )
    } else {
        let octets = val.to_be_bytes();
        let v6 = std::net::Ipv6Addr::new(
            u16::from_be_bytes([octets[0], octets[1]]),
            u16::from_be_bytes([octets[2], octets[3]]),
            u16::from_be_bytes([octets[4], octets[5]]),
            u16::from_be_bytes([octets[6], octets[7]]),
            u16::from_be_bytes([octets[8], octets[9]]),
            u16::from_be_bytes([octets[10], octets[11]]),
            u16::from_be_bytes([octets[12], octets[13]]),
            u16::from_be_bytes([octets[14], octets[15]]),
        );
        v6.to_string()
    }
}
