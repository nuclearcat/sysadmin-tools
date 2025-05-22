use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use pcap::{Capture, Offline};

fn save_packets(pcap_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pcap_file = Path::new(pcap_path);
    let stem = pcap_file.file_stem().unwrap().to_string_lossy();
    let out_dir = pcap_file.with_file_name(stem.as_ref());
    fs::create_dir_all(&out_dir)?;

    let mut cap = Capture::<Offline>::from_file(pcap_path)?;
    let mut idx = 0;
    while let Ok(packet) = cap.next_packet() {
        let out_path = out_dir.join(format!("packet_{:05}.bin", idx));
        let mut out_file = File::create(out_path)?;
        out_file.write_all(packet.data)?;
        idx += 1;
    }
    println!("Extracted {} packets to {:?}", idx, out_dir);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input.pcap>", args[0]);
        std::process::exit(1);
    }
    if let Err(e) = save_packets(&args[1]) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}