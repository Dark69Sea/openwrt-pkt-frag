#!/bin/bash
# Quick test using nftables (no kernel module needed)
# Fragments packets using iptables/nftables

set -e

FRAG_SIZE=${1:-512}
INTERFACE=${2:-wan}

echo "Setting up packet fragmentation (size=$FRAG_SIZE) on $INTERFACE"

# IPv4: Use iptables with NFQUEUE + userspace fragmenter
# Or use tc with u32 filter (kernel only, limited)

# Method 1: nftables + nfqueue (requires userspace daemon)
cat <<EOF > /etc/nftables.d/pkt-frag.nft
table inet pkt_frag {
    chain output {
        type filter hook output priority 0; policy accept;
        meta l4proto { tcp, udp } counter queue num 0-3
    }
}
EOF

# Method 2: tc (traffic control) - kernel only, no daemon
# Only works for egress, limited fragmentation control

# For Google Router (ARM64), the kernel module is recommended
echo "For production, use the kernel module (kmod-pkt-frag)"
echo "This script is for testing only"