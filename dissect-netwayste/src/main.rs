use bincode::deserialize;
use clap::{self, Parser};
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
        short,
        long,
        help = "Specify a custom, valid Berkeley Packet Filter (BPF) string. Default is 'udp port <port>'"
    )]
    custom_bpf: Option<String>,
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

                match ethernet.transport {
                    // Filter away non-netwayste packets based on the source and destination port
                    Some(Udp(udp)) => {
                        if udp.source_port() != NETWAYSTE_PORT
                            && udp.destination_port() != NETWAYSTE_PORT
                        {
                            continue;
                        }

                        src_port = udp.source_port();
                    }
                    _ => continue,
                }

                match ethernet.ip {
                    Some(Ipv4(ipv4, _extensions)) => {
                        src_ip = ipv4.source_addr();
                    }
                    _ => continue,
                }

                // There's a packet that is candidate for matching netwayste
                match deserialize::<Packet>(ethernet.payload) {
                    Ok(nw_packet) => {
                        info!("{:>15?}:{:<5} {:?}", src_ip, src_port, nw_packet);
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
