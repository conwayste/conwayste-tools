# Setup

Requires `rust-pcap`. See its [dependency installation](https://github.com/rust-pcap/pcap#installing-dependencies) section for more details.

Build the crate and then modify the permissions so we can call into libpcap as `$USER`.

```bash
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/dissect-netwayste
```
