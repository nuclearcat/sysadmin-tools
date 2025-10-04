/**********************************************************************
 * Rust implementation of network traffic monitoring tool
 * Compile with:
 * cargo build --release
 *
 **********************************************************************/

use chrono::prelude::*;
use etherparse::{Ethernet2Header, InternetSlice, SlicedPacket};
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::process;
use std::time::Instant;
use std::io::Write;

 
 const REPORT_DST: u8 = 0;
 const REPORT_SRC: u8 = 1;
 
#[derive(Debug)]
struct Report {
    direction: u8,
    mask: u8,
}

#[derive(Debug)]
struct IpPair {
    addr: u32,
    bytes: u64,
    packets: u32,
}
 
#[derive(Debug)]
struct Stats {
    packets_total: u64,
    bytes: u64,
    start_time: Instant,
    pairs: HashMap<u32, IpPair>,
    report: Report,
    packets_trigger: i32,
    sort_by: i32,
    report_count: i32,
    report_csv: u32,
}
 
impl Stats {
    fn new(report: Report, packets: i32, sort_by: i32, report_count: i32, report_csv: u32) -> Self {
        Stats {
            packets_total: 0,
            bytes: 0,
            start_time: Instant::now(),
            pairs: HashMap::new(),
            report,
            packets_trigger: packets / 5,
            sort_by,
            report_count,
            report_csv,
        }
    }

    fn add_ip(&mut self, ipaddr: u32, bytes: usize) {
        let masked_ip = ipaddr & self.fill_bits(self.report.mask);

        let entry = self.pairs.entry(masked_ip).or_insert(IpPair {
            addr: masked_ip,
            bytes: 0,
            packets: 0,
        });

        entry.packets += 1;
        entry.bytes += bytes as u64;
    }

    fn fill_bits(&self, mask: u8) -> u32 {
        let mut bits: u32 = 0;
        for i in 0..mask {
            bits |= 1 << (31 - i);
        }
        bits
    }

    fn show_stats(&self) {
        let elapsed = self.start_time.elapsed();
        let elapsed_ms = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis());

        // Clear screen if we are in "report_count" mode
        if self.report_count > 0 {
            print!("\x1B[2J\x1B[1;1H"); // ANSI escape code to clear screen
        }

        // Convert HashMap to Vec for sorting
        let mut pairs_vec: Vec<&IpPair> = self.pairs.values().collect();

        // Sort by bytes or packets
        if self.sort_by == 0 || self.sort_by == 2 {
            pairs_vec.sort_by(|a, b| a.bytes.cmp(&b.bytes));
        } else if self.sort_by == 1 {
            pairs_vec.sort_by(|a, b| a.packets.cmp(&b.packets));
        }

        // Show last 100 entries (or less if we don't have that many)
        let start_idx = if pairs_vec.len() > 100 { pairs_vec.len() - 100 } else { 0 };
        
        for pair in &pairs_vec[start_idx..] {
            let ip = Ipv4Addr::from(pair.addr);
            let avg_bytes = if pair.packets > 0 { pair.bytes / pair.packets as u64 } else { 0 };
            let bytes_percentage = if self.bytes > 0 { pair.bytes * 100 / self.bytes } else { 0 };
            let packets_percentage = if self.packets_total > 0 { pair.packets as u64 * 100 / self.packets_total } else { 0 };
            let kbits_per_sec = if elapsed_ms > 0 { pair.bytes * 8 / elapsed_ms } else { 0 };
            let mut ip_str = ip.to_string();
            // if dst24 or src24, then add /24 to the ip_str
            if self.report.mask == 24 {
                ip_str = format!("{}/24", ip_str);
            }

            println!(
                "{:<15} {}b {}p avg {}b {}%b {}%p {} Kbit/s",
                ip_str,
                pair.bytes,
                pair.packets,
                avg_bytes,
                bytes_percentage,
                packets_percentage,
                kbits_per_sec
            );
        }

        let avg_packet_size = if self.packets_total > 0 {
            self.bytes / self.packets_total
        } else {
            0
        };

        println!(
            "Average packet size {} (with ethernet header, max avg sz 1514)",
            avg_packet_size
        );

        println!(
            "Time {}, total bytes {}, total speed {} Kbit/s",
            elapsed_ms,
            self.bytes,
            if elapsed_ms > 0 { self.bytes * 8 * 1000 / elapsed_ms / 1024 } else { 0 }
        );

        // If report_count not zero, then exit
        if self.report_count > 0 {
            process::exit(0);
        }
     }
    fn output_csv(&self) {
        let mut filename: String = "report.csv".to_string();

        // iterate for from 0 to 999 to find first available reportNNN.csv
        for i in 0..1000 {
            filename = format!("report{}.csv", i);
            if !std::path::Path::new(&filename).exists() {
                break;
            }
        }
        println!("Writing CSV report to {}", filename);

        let mut file = std::fs::File::create(filename).expect("Unable to create file");

        writeln!(file, "IP,Bytes,Packets,Avg Bytes,Bytes Percentage,Packets Percentage,Kbit/s").expect("Unable to write header");

        for pair in self.pairs.values() {
            let ip = Ipv4Addr::from(pair.addr);
            let avg_bytes = if pair.packets > 0 { pair.bytes / pair.packets as u64 } else { 0 };
            let bytes_percentage = if self.bytes > 0 { pair.bytes * 100 / self.bytes } else { 0 };
            let packets_percentage = if self.packets_total > 0 { pair.packets as u64 * 100 / self.packets_total } else { 0 };
            let kbits_per_sec = if self.start_time.elapsed().as_millis() > 0 {
                pair.bytes * 8 * 1000 / self.start_time.elapsed().as_millis() as u64 / 1024
            } else {
                0
            };
            writeln!(
                file,
                "{},{},{},{},{},{},{}",
                ip,
                pair.bytes,
                pair.packets,
                avg_bytes,
                bytes_percentage,
                packets_percentage,
                kbits_per_sec
            ).expect("Unable to write data");
        }
    }
 }
 
fn process_packet(packet_raw: &[u8], stats: &mut Stats) {
    stats.packets_total += 1;
    stats.bytes += packet_raw.len() as u64;

    // check if output_csv is set and seconds have passed
    // calculate elapsed time in seconds
    let elapsed_secs = stats.start_time.elapsed().as_secs();
    if stats.report_csv > 0 && elapsed_secs > stats.report_csv as u64 {
        stats.output_csv();
        // quite
        println!("CSV report generated, exiting.");
        process::exit(0);
        //stats.start_time = Instant::now(); // reset start time after outputting CSV
    }

    // Show stats periodically based on packet count
    if stats.packets_total % stats.packets_trigger as u64 == 0 {
        stats.show_stats();
    }
    // If this is PPPoE/PPP encapsulated packet, make offset
    // and decode IP again
    let mut packet = packet_raw;
    // ethernet header size is 14 bytes
    // PPPoE header size is 6 bytes, PPP header size is 2 bytes
    // offset ethernet + PPPoE/PPP headers
    // total offset to skip is 14 + 6 + 2 = 22 bytes
    if packet.len() > 22 && packet[12..14] == [0x88, 0x64] {
    packet = &packet[22..]; // Skip Ethernet and PPPoE/PPP headers
    // PPPoE packet detected
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        // IPv4 packet detected
        match SlicedPacket::from_ip(packet) {
            Ok(sliced) => {
                if let Some(InternetSlice::Ipv4(ipv4_header, _)) = sliced.ip {
                    // Extract source or destination IP based on direction
                    let ipaddr = if stats.report.direction == REPORT_SRC {
                        u32::from_be_bytes(ipv4_header.source_addr().octets())
                    } else {
                        u32::from_be_bytes(ipv4_header.destination_addr().octets())
                    };

                    // Add IP to stats
                    stats.add_ip(ipaddr, packet.len());
                }
            }
            Err(_) => {
                // Packet couldn't be parsed, ignore it
            }
        }
        return;
        } else {
            // Not IPv4 packet, ignore it
            return;
        }
    }

    // Parse the packet using etherparse
    match SlicedPacket::from_ethernet(packet) {
        Ok(sliced) => {
            if let Some(InternetSlice::Ipv4(ipv4_header, _)) = sliced.ip {
                // Extract source or destination IP based on direction
                let ipaddr = if stats.report.direction == REPORT_SRC {
                    u32::from_be_bytes(ipv4_header.source_addr().octets())
                } else {
                    u32::from_be_bytes(ipv4_header.destination_addr().octets())
                };

                // Add IP to stats
                stats.add_ip(ipaddr, packet.len());
            }
        }
        Err(_) => {
            // Packet couldn't be parsed, ignore it
        }
    }
}

fn usage() {
    let args: Vec<String> = env::args().collect();
    println!("iptop v3.1 (Rust port)");
    println!("Usage: {} interface \"pcap filter\" packets (dst|src|dst24|src24) [--report=NNN]", args[0]);
    println!("p - sort by packets, b - by bytes (default)");
    println!("dst - report destination IPs, src - source IPs, dst24 - /24 destination IPs, src24 - /24 source IPs");
    println!("packets - number of packets to capture, must be a positive integer");
    println!("--report - report in CSV format, default is report.csv, after NNN seconds");
    println!("Example: {} eth0 \"tcp port 80\" 1000 dst --report=60", args[0]);
    println!("This will capture 1000 packets on eth0 with TCP port 80 filter, report destination IPs every 60 seconds in CSV format.");
    process::exit(1);
}
 
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 5 {
        usage();
        return Ok(());
    }

    let interface = &args[1];
    let filter = &args[2];
    let packets: i32 = args[3].parse()?;
    let direction = &args[4];
    let mut report_csv: u32 = 0;

    if args.len() > 5 && args[5].starts_with("--report=") {
        report_csv = args[5].split('=').nth(1).unwrap_or("60").parse::<u32>().unwrap_or(60);
    }
     
    let mut sort_by = 0;

    // Set up report configuration
    let mut report = Report {
        direction: REPORT_DST,
        mask: 32,
    };

    match direction.as_str() {
        "src" => {
            report.direction = REPORT_SRC;
        }
        "dst" => {
            report.direction = REPORT_DST;
        }
        "src24" => {
            report.direction = REPORT_SRC;
            report.mask = 24;
        }
        "dst24" => {
            report.direction = REPORT_DST;
            report.mask = 24;
        }
        _ => {}
    }
    // validate packets is a positive integer
    if packets <= 0 {
            println!("invalid packets (positive integer)");
            usage();
            return Ok(());
    }

        // validate sort_by is a positive integer
    if sort_by <= 0 {
        // default sort by bytes
        sort_by = 2;
    }

        // Get report_count from environment variable
    let report_count = env::var("REPORT_COUNT")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<i32>()
            .unwrap_or(0);

            // validate report_count is a positive integer
    if report_count < 0 {
        println!("invalid report_count (0 or more)");
        usage();
        return Ok(());
    }

    let device : &str = interface;

    let mut cap = Capture::from_device(device)?
        .promisc(false)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

        // Set the filter
    cap.filter(filter.as_str(), true)?;

    // Initialize statistics
    let mut stats = Stats::new(report, packets, sort_by, report_count, report_csv);

    
    // Start packet capture loop
    loop {
        let packet = cap.next_packet();
        match packet {
        Ok(packet) => {
            process_packet(&packet.data, &mut stats);
        }
        Err(e) => {
            if e == pcap::Error::TimeoutExpired {
                continue;
            }
            println!("error: {:?}", e);
            process::exit(1);
        }
        }
    }
    Ok(())
}
