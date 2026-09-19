#!/bin/bash
# Test script for packet fragmentation module

set -e

echo "=== Testing pkt-frag module ==="

# Load module
echo "Loading module..."
insmod pkt_frag.ko frag_size=256 enable_tcp=1 enable_udp=1

echo "Module parameters:"
cat /sys/module/pkt_frag/parameters/*

echo ""
echo "Testing with ping (ICMP - should NOT fragment)..."
ping -c 2 -s 1000 8.8.8.8 || true

echo ""
echo "Testing with netcat TCP (should fragment)..."
# Requires a listening server
# nc -v 1.2.3.4 80 < /dev/zero &

echo ""
echo "Testing with netcat UDP (should fragment)..."
# nc -u -v 1.2.3.4 53 < /dev/zero &

echo ""
echo "Check kernel log for pkt_frag messages:"
dmesg -T | grep pkt_frag | tail -20

echo ""
echo "Unloading module..."
rmmod pkt_frag

echo "Test complete"