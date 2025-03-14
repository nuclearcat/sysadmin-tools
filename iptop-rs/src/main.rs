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
 }
 
 impl Stats {
     fn new(report: Report, packets: i32, sort_by: i32, report_count: i32) -> Self {
         Stats {
             packets_total: 0,
             bytes: 0,
             start_time: Instant::now(),
             pairs: HashMap::new(),
             report,
             packets_trigger: packets / 5,
             sort_by,
             report_count,
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
 }
 
 fn process_packet(packet: &[u8], stats: &mut Stats) {
     stats.packets_total += 1;
     stats.bytes += packet.len() as u64;
 
     // Show stats periodically based on packet count
     if stats.packets_total % stats.packets_trigger as u64 == 0 {
         stats.show_stats();
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
    println!("iptop v3 (Rust port)");
    println!("Usage: {} interface \"pcap filter\" packets (dst|src|dst24|src24) [p|b]", args[0]);
    println!("p - sort by packets, b - by bytes (default)");
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
     
     let mut sort_by = 0;
     if args.len() == 6 {
         match args[5].as_str() {
             "p" => sort_by = 1,
             "b" => sort_by = 2,
             _ => {}
         }
     }
 
     // Set up report configuration
     let mut report = Report {
         direction: REPORT_DST,
         mask: 32,
     };
 
     match direction.as_str() {
         "src" => {
             report.direction = REPORT_SRC;
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
         println!("invalid sort_by (packets or bytes)");
         usage();
         return Ok(());
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
     let mut stats = Stats::new(report, packets, sort_by, report_count);
 
     
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
