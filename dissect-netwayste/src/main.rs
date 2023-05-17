use bincode::deserialize;
use clap::{self, Parser};
use etherparse::{SlicedPacket, TransportSlice::Udp};
use netwaystev2::{protocol::Packet, DEFAULT_PORT};
use pcap;
use tracing::*;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Log all failed de-serialization attempts")]
    verbose: bool,
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.) will be written to stdout.
        .with_max_level(Level::TRACE)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args = Args::parse();

    // Verify we can find a device
    let _ = pcap::Device::list().expect("device lookup failed");

    // get the default Device
    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");

    info!("Using device '{}'", device.name);

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter(format!("udp port {:?}", DEFAULT_PORT).as_str(), true)
        .expect("failed to filter for netwayste packets");

    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(packet.data) {
            Err(err) => {
                panic!("deserializing EthernetII packet: {}", err);
            }
            Ok(ethernet) => {
                match ethernet.transport {
                    Some(Udp(udp)) => {
                        // Filter away non-netwayste packets based on the source and destination port
                        if udp.source_port() != DEFAULT_PORT
                            && udp.destination_port() != DEFAULT_PORT
                        {
                            continue;
                        }
                    }
                    _ => continue,
                }

                // There's a packet that is candidate for matching netwayste
                match deserialize::<Packet>(ethernet.payload) {
                    Ok(nw_packet) => {
                        info!("{:?}", nw_packet);
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
