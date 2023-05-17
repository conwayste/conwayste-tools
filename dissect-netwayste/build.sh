#!/usr/bin/env bash

usage() {
cat << EOF
Usage: $0 [-rh]
Build and set packet capture permissions on the target binary.

-h      Display help

-r      Run the target executable after a successful build
EOF
    exit 0
}

while getopts ":h:r" arg; do
    case "${arg}" in
        r)
            run=true
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

which setcap > /dev/null || echo "'setcap' could not be found"
cargo build && sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/dissect-netwayste

if [ ${run} ]; then
    cargo run
fi
