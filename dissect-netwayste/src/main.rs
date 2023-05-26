use std::fmt;
use std::{collections::HashMap, net::Ipv4Addr, vec};

use bincode::deserialize;
use circular_vec::CircularVec;
use clap::{self, Parser, ValueEnum};
use colored::*;
use etherparse::{InternetSlice::Ipv4, SlicedPacket, TransportSlice::Udp};
use netwaystev2::{protocol::Packet, DEFAULT_PORT as NETWAYSTE_PORT};
use pcap;
use tracing::*;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Log all failed de-serialization attempts")]
    verbose: bool,

    #[arg(short, long, help = "The network interface name")]
    interface: Option<String>,

    #[arg(short, long, default_value_t = NETWAYSTE_PORT, help = "This has no effect if 'custom-bpf' is provided")]
    port: u16,

    #[arg(
        long,
        default_value = "ip-and-port",
        help = "Control how packets are colorized"
    )]
    color_option: ColorOption,

    #[arg(
        short,
        long,
        help = "Specify a custom, valid Berkeley Packet Filter (BPF) string. Default is 'udp port <port>'"
    )]
    custom_bpf: Option<String>,
}

#[derive(Parser, ValueEnum, Debug, Clone)]
enum ColorOption {
    IPAndPort,
    OnlyIP,
    NoColor,
}

impl ColorOption {
    fn color_enabled(&self) -> bool {
        match self {
            ColorOption::NoColor => false,
            _ => true,
        }
    }
}

impl fmt::Display for ColorOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        // All spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.) will be written to stdout.
        .with_max_level(Level::TRACE)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args = Args::parse();

    // Setup Capture
    let device = if let Some(interface) = args.interface {
        // Verify we can find a device
        let device_list = pcap::Device::list().expect("Could not access network interface list");
        device_list
            .into_iter()
            .filter(|d| d.name == interface)
            .next()
            .expect(&format!(
                "Failed to find '{}' in network interface list",
                interface
            ))
    } else {
        pcap::Device::lookup()
            .expect("Failed to look up default device")
            .unwrap()
    };

    let device_name = device.name.clone();

    // Unwrap okay because of device verification above
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut filter_string = format!("udp port {:?}", args.port);
    if let Some(filter) = args.custom_bpf {
        let dead_capture = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
        dead_capture
            .compile(&filter, true)
            .ok()
            .expect("Failed to compile custom-bpf");
        filter_string = filter;
    }

    cap.filter(&filter_string, true)
        .expect("Failed to filter for netwayste packets");

    info!(
        "Listening to device '{}' with filter '{}'",
        device_name, filter_string
    );

    let mut ip_color_map = HashMap::<(Ipv4Addr, Option<u16>), Color>::new();

    // Colors are specified to reduce adjacent similarity.
    // This may appear differently depending on one's terminal settings.
    let mut color_list: CircularVec<Color> = vec![
        Color::Cyan,
        Color::Yellow,
        Color::Red,
        Color::Magenta,
        Color::Green,
        Color::Blue,
    ]
    .into_iter()
    .collect();

    // TODO: some next_packet() errors should just be logged, rather than breaking out of the loop.
    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(packet.data) {
            Err(err) => {
                if args.verbose {
                    error!("Failed EthernetII packet de-serialization: '{}'", err);
                }
            }
            Ok(ethernet) => {
                let src_port;
                let src_ip;

                // Ignore non-UDP.
                match ethernet.transport {
                    Some(Udp(udp)) => {
                        src_port = udp.source_port();
                    }
                    _ => continue,
                }
                let mut message_color: Option<Color> = None;
                match ethernet.ip {
                    Some(Ipv4(ipv4, _extensions)) => {
                        src_ip = ipv4.source_addr();
                        let key = match args.color_option {
                            ColorOption::IPAndPort => (src_ip, Some(src_port)),
                            _ => (src_ip, None),
                        };

                        if args.color_option.color_enabled() {
                            match ip_color_map.get_mut(&key) {
                                Some(entry) => message_color = Some(*entry),
                                None => {
                                    message_color = Some(*color_list.next());
                                    ip_color_map.insert(key.clone(), message_color.unwrap());
                                }
                            }
                        }
                    }
                    _ => continue,
                }

                // There's a packet that is candidate for matching netwayste
                match deserialize::<Packet>(ethernet.payload) {
                    Ok(nw_packet) => {
                        let message = format!("{:>15?}:{:<5} {:?}", src_ip, src_port, nw_packet);
                        if args.color_option.color_enabled() {
                            info!("{}", message.color(message_color.unwrap()));
                        } else {
                            info!("{}", message);
                        }
                    }
                    Err(e) => {
                        if args.verbose {
                            error!("Failed de-serialization: '{}'", e);
                            error!("Failed packet contents: '{:?}'", ethernet.payload);
                        }
                    }
                }
            }
        }
    }
}
