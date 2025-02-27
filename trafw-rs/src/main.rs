use chrono::Utc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::env;
use crossbeam::channel::{unbounded, Receiver};
use lazy_static::lazy_static;
use pcap::{Capture, Packet};

// Configuration constants
const IEC_COMPLIANT: bool = true;
const DIVIDER: u64 = if IEC_COMPLIANT { 1000 } else { 1024 };
const KBITNAME: &str = if IEC_COMPLIANT { "KBit" } else { "KiBit" };
const BILLION: f64 = 1_000_000_000.0;

// Global statistics
struct TrafficStats {
    traf: [u64; 2],
    pkts: [u32; 2],
    overall: [u64; 2],
}

lazy_static! {
    static ref STATS: Arc<Mutex<TrafficStats>> = Arc::new(Mutex::new(TrafficStats {
        traf: [0, 0],
        pkts: [0, 0],
        overall: [0, 0],
    }));
}

fn packet_callback(interface_index: usize, packet: Packet) {
    let caplen = std::cmp::max(packet.len() as u64 + 4, 64); // FCS + Ethernet minimum
    
        let mut stats = STATS.lock().unwrap();
        stats.pkts[interface_index] += 1;
        stats.traf[interface_index] += caplen;
}

fn show_traffic(old_time: &mut f64, args_len: usize) {
    let now = Utc::now().timestamp_nanos() as f64 / BILLION;
    let elapsed = now - *old_time;

    if elapsed >= 1.0 {
        let mut stats = STATS.lock().unwrap();
        
        let local_traf = stats.traf;
        let local_pkts = stats.pkts;
        
        stats.traf = [0, 0];
        stats.pkts = [0, 0];

        let s = (Utc::now().timestamp() % 86400) as u32;
        print!(
            "{:02}:{:02}:{:02} ",
            s / 3600,
            (s % 3600) / 60,
            s % 60
        );

        if args_len == 6 {
            println!(
                "{}/{} {}/S {}/{} pps ({}/{}) ({}/{}) {:.2}",
                local_traf[0] * 8 / elapsed as u64 / DIVIDER,
                local_traf[1] * 8 / elapsed as u64 / DIVIDER,
                KBITNAME,
                local_pkts[0] / elapsed as u32,                
                local_pkts[1] / elapsed as u32,
                local_traf[0],
                local_traf[1],
                stats.overall[0],
                stats.overall[1],
                elapsed
            );
        } else {
            println!(
                "{} {}/S {} pps ({}/{}) {:.2}",
                local_traf[0] * 8 / elapsed as u64 / DIVIDER,
                KBITNAME,
                local_pkts[0] / elapsed as u32,
                local_traf[0],
                stats.overall[0],
                elapsed
            );
        }
        stats.overall[0] += local_traf[0];
        if args_len == 6 {
            stats.overall[1] += local_traf[1];
        }
        *old_time = now;
    }
}

fn capture_interface(interface_name: &str, filter: &str, index: usize) {
    let mut cap = Capture::from_device(interface_name)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
        
    cap.filter(filter, true).expect("Error setting filter");

    let _ = cap.for_each(None, |packet| {
        packet_callback(index, packet);
    });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 6 && args.len() != 4 {
        println!(
            "Usage: {} interface1 \"filter1\" [interface2 \"filter2\"] timer",
            args[0]
        );
        return;
    }
    let timer: u64;
    if args.len() == 4 {
        timer = args[3].parse().expect("Invalid timer value");
    } else {
        timer = args[5].parse().expect("Invalid timer value");
    }

    if timer == 0 {
        println!("Wrong timer!");
        return;
    }

    let interface1 = args[1].clone();
    let filter1 = args[2].clone();
    // Start capture threads
    thread::spawn(move || {
        capture_interface(&interface1, &filter1, 0);
    });
    if args.len() == 6 {
        let interface2 = args[3].clone();
        let filter2 = args[4].clone();
    
        thread::spawn(move || {
            capture_interface(&interface2, &filter2, 1);
        });
    }

    let mut old_time = Utc::now().timestamp_nanos() as f64 / BILLION;

    loop {
        thread::sleep(Duration::from_secs(timer));
        show_traffic(&mut old_time, args.len());
    }
}