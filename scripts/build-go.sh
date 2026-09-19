#!/bin/bash
# Cross-compile Go userspace daemon for OpenWrt ARM64

set -e

TARGET=${1:-aarch64-openwrt-linux-musl}
GOARCH=arm64
GOOS=linux

export CGO_ENABLED=1
export CC=${TARGET}-gcc
export GOARCH=${GOARCH}
export GOOS=${GOOS}

cd "$(dirname "$0")/../userspace"

go mod tidy
go build -ldflags="-s -w" -o pkt-frag-daemon main.go

echo "Built: pkt-frag-daemon"
file pkt-frag-daemon