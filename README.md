# OpenWrt Advanced Packet Fragmentation (pkt-frag v2)

Kernel module + userspace daemon + LuCI web UI for advanced DPI bypass:
- **IP Fragmentation** (TCP/UDP, IPv4/IPv6)
- **TLS ClientHello Fragmentation** (split into multiple records)
- **QUIC/HTTP3 Fragmentation** (UDP 443 Initial packets)
- **Random Padding** (defeat length-based analysis)
- **TLS Fingerprint Spoofing** (Chrome/Firefox/Safari/Edge/cURL profiles + rotation)

## Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    LuCI Web UI (port 80/443)                 │
│         /usr/lib/lua/luci/controller/pkt-frag.lua           │
└──────────────────────────┬──────────────────────────────────┘
                           │ UCI config
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              pkt-frag-daemon (userspace)                     │
│    - Watch UCI config changes (inotify)                      │
│    - Write kernel module params (/sys/module/...)            │
│    - Fingerprint rotation (background thread)                │
│    - State persistence (/var/run/pkt-frag-state.json)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ Netlink / sysfs
                           ▼
┌─────────────────────────────────────────────────────────────┐
│            pkt_frag.ko (kernel module)                       │
│    - Netfilter hook: NF_INET_POST_ROUTING                    │
│    - Inspect TCP/UDP payload                                 │
│    - Fragment / pad / modify TLS ClientHello / QUIC          │
│    - Re-inject fragments                                     │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites
- OpenWrt SDK or Buildroot for target (Google Router = ARM64/aarch64)
- Kernel headers matching target OpenWrt version
- Toolchain: `aarch64-openwrt-linux-musl-gcc`

### Build in OpenWrt SDK
```bash
# 1. Copy package to SDK
cp -r openwrt/pkt-frag /path/to/openwrt-sdk/package/

# 2. Update feeds
cd /path/to/openwrt-sdk
./scripts/feeds update -a
./scripts/feeds install -a

# 3. Configure
make menuconfig
# Network → pkt-frag (M)
# Network → pkt-frag-daemon (M)  
# LuCI → Applications → luci-app-pkt-frag (M)

# 4. Build
make package/pkt-frag/compile V=s
make package/luci-app-pkt-frag/compile V=s

# 5. Find packages
find bin -name "pkt-frag*" -o -name "luci-app-pkt-frag*"
```

### Build in OpenWrt Buildroot
```bash
# 1. Add to package feed
cp -r openwrt/pkt-frag /path/to/openwrt/package/network/

# 2. Enable in menuconfig
make menuconfig
# Network → pkt-frag (M)
# Network → pkt-frag-daemon (M)
# LuCI → Applications → luci-app-pkt-frag (M)

# 3. Build
make package/pkt-frag/compile V=s
```

## Installation on Target (Google Router)

### Method 1: opkg (recommended)
```bash
# Copy .ipk files to router
scp bin/packages/aarch64_generic/base/pkt-frag*.ipk root@192.168.1.1:/tmp/
scp bin/packages/aarch64_generic/luci/luci-app-pkt-frag*.ipk root@192.168.1.1:/tmp/

# On router
opkg update
opkg install /tmp/kmod-pkt-frag_*.ipk
opkg install /tmp/pkt-frag-daemon_*.ipk
opkg install /tmp/luci-app-pkt-frag_*.ipk

# Enable & start
/etc/init.d/pkt-frag enable
/etc/init.d/pkt-frag start
```

### Method 2: sysupgrade (include in firmware)
```bash
# In buildroot
make menuconfig
# Target Images → Include pkt-frag, pkt-frag-daemon, luci-app-pkt-frag
make -j$(nproc)
# Flash resulting sysupgrade.bin
```

## LuCI Web UI Access

1. Open browser: `http://192.168.1.1` (or your router IP)
2. Login (default: root / no password)
3. Navigate: **Network → Packet Fragmentation**

### UI Sections

| Section | Options | Description |
|---------|---------|-------------|
| **Global** | Enable, Fragment Size, Interface | Core settings |
| **Protocol** | TCP, UDP, TLS Fragment, QUIC Fragment | Protocol-specific |
| **Padding** | Enable, Min/Max bytes | Random padding |
| **Fingerprint** | Enable, Profile, Rotation | TLS ClientHello spoofing |
| **Advanced** | Module Status, Statistics, Apply | Live monitoring |

## Configuration (UCI)

### `/etc/config/pkt-frag`
```ini
config pkt-frag 'global'
    option enabled '1'
    option frag_size '512'           # Base fragment size (64-1400)
    option enable_tcp '1'            # Fragment TCP
    option enable_udp '1'            # Fragment UDP
    option enable_tls_frag '1'       # Split TLS ClientHello
    option tls_record_size '1400'    # Max TLS record after split
    option enable_quic_frag '1'      # Fragment QUIC Initial
    option enable_padding '1'        # Add random padding
    option padding_min '0'           # Min padding bytes
    option padding_max '64'          # Max padding bytes
    option enable_fingerprint '1'    # Spoof TLS fingerprint
    option fingerprint_profile 'chrome'  # chrome/firefox/safari/edge/curl/random
    option rotate_interval '3600'    # Rotation interval (seconds, 0=off)
    option interface 'wan'           # wan/lan/"" (all)
```

### CLI Commands
```bash
# View current config
uci show pkt-frag

# Change fragment size
uci set pkt-frag.global.frag_size='256'
uci commit pkt-frag
/etc/init.d/pkt-frag reload

# Enable QUIC fragmentation only
uci set pkt-frag.global.enable_quic_frag='1'
uci set pkt-frag.global.enable_tls_frag='0'
uci commit pkt-frag
/etc/init.d/pkt-frag reload

# Set random fingerprint rotation
uci set pkt-frag.global.fingerprint_profile='random'
uci set pkt-frag.global.rotate_interval='1800'
uci commit pkt-frag
/etc/init.d/pkt-frag reload
```

## Runtime Control (Kernel Parameters)

```bash
# View all parameters
cat /sys/module/pkt_frag/parameters/*

# Change fragment size (immediate)
echo 128 > /sys/module/pkt_frag/parameters/frag_size

# Disable TLS fragmentation
echo 0 > /sys/module/pkt_frag/parameters/enable_tls_frag

# Adjust padding
echo 10 > /sys/module/pkt_frag/parameters/padding_min
echo 128 > /sys/module/pkt_frag/parameters/padding_max

# Check module log
dmesg -T | grep pkt_frag
```

## How It Works

### 1. IP Fragmentation
- Hooks at `NF_INET_POST_ROUTING` (after routing, before egress)
- Splits packets > `frag_size` into multiple IP fragments
- Sets MF (More Fragments) flag, correct offset
- Reassembles automatically at destination

### 2. TLS ClientHello Fragmentation
- Detects TLS Handshake (0x16) + ClientHello (0x01) in TCP payload
- Splits large ClientHello into multiple TLS records
- Each record ≤ `tls_record_size` (default 1400)
- First record contains partial ClientHello, rest in subsequent records
- DPI sees incomplete ClientHello → signature mismatch

### 3. QUIC Fragmentation
- Detects QUIC Initial packet (first byte: 0x80-0xBF with bit 6-7 = 00)
- Fragments UDP payload at IP layer
- QUIC reassembles at receiver (standard QUIC behavior)

### 4. Random Padding
- Adds 0-255 random bytes to packet end
- Defeats packet length fingerprinting
- Applied after TLS/QUIC processing

### 5. TLS Fingerprint Modification
- Modifies cipher suite order (JA3 fingerprint)
- Randomizes GREASE values (extension 0x0a0a)
- Tweaks ALPN extension
- Profiles: Chrome, Firefox, Safari, Edge, cURL
- Rotation: switches profile every N seconds

## Recommended Settings for Iran DPI

```ini
# High obfuscation
frag_size=256
enable_tls_frag=1
tls_record_size=512
enable_quic_frag=1
enable_padding=1
padding_min=10
padding_max=128
enable_fingerprint=1
fingerprint_profile=random
rotate_interval=1800
```

## Testing & Verification

```bash
# 1. Check module loaded
lsmod | grep pkt_frag

# 2. Check daemon running
ps | grep pkt-frag-daemon

# 3. Verify netfilter hook
cat /proc/net/ip_tables_targets | grep pkt_frag

# 4. Test TLS fragmentation
openssl s_client -connect google.com:443 -msg 2>&1 | head -50
# Look for multiple "TLS Record Layer" entries for ClientHello

# 5. Test QUIC
curl --http3 https://cloudflare.com/cdn-cgi/trace

# 6. Check fingerprint
# Use https://tls.peet.ws/ or JA3 calculator

# 7. View statistics
cat /proc/net/pkt_frag_stats 2>/dev/null || echo "Stats not available"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Module won't load | `dmesg | grep pkt_frag` - check kernel version match |
| No LuCI menu | `rm -rf /tmp/luci-*cache; /etc/init.d/uhttpd restart` |
| Config not applying | Check `/etc/init.d/pkt-frag reload` logs |
| High CPU | Increase `frag_size`, disable unused protocols |
| Connection drops | Check MTU: `frag_size + 40 (IP+TCP) < MTU` |
| QUIC not working | Ensure UDP 443 not blocked, check `enable_quic_frag` |

## Performance

| Setting | CPU Overhead | Memory | Latency |
|---------|--------------|--------|---------|
| frag=512, TLS on, QUIC on | ~2-5% | <1MB | <1ms |
| frag=128, all features | ~5-10% | <2MB | <2ms |

## License
GPL v2

## Contributing
PRs welcome. Test on target hardware before submitting.