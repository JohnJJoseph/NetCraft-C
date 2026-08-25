# NetCraft-C
# Low-Level Network Security Toolkit
# Light weight version if Nmap

NetCraft-C is a lightweight C toolkit for low-level network security tasks. It provides a collection of command-line tools for port scanning, packet sniffing, and ARP spoofing, designed for educational use and network diagnostics.

## Features

- **SYN Scanner** — Raw socket TCP SYN port scanner (requires root). Sends crafted TCP SYN packets and listens for SYN-ACK responses to identify open ports.
- **Connect Scanner** — TCP connect() port scanner (no root required). Multi-threaded for fast scanning of configurable port ranges.
- **Packet Sniffer** — Packet capture using libpcap. Supports protocol filtering (tcp, udp, icmp, arp) with hex payload dump.
- **ARP Spoofer** — ARP spoofing tool for educational MITM demonstrations (requires root). Automatically restores ARP tables on exit.

## Build

```bash
# Build all tools
make

# Build individual tools
make syn-scanner
make connect-scanner
make sniffer
make arp-spoof

# Clean build artifacts
make clean
```

**Dependencies:** POSIX-compliant system with GCC. The packet sniffer requires `libpcap-dev`.

## Usage

### SYN Scanner
```bash
sudo ./syn-scanner 192.168.1.1 1-1024
```

### Connect Scanner
```bash
./connect-scanner 192.168.1.1 22-443 -t 50
```

### Packet Sniffer
```bash
sudo ./sniffer eth0 tcp -c 10
```

### ARP Spoofer
```bash
sudo ./arp-spoof 192.168.1.100 192.168.1.1 eth0
```

## Ethical Use Warning

This software is intended **only** for:
- Authorized security testing on systems you own or have explicit permission to test.
- Educational purposes to understand network protocols and security concepts.

Unauthorized use of these tools against systems you do not own may violate applicable laws. The authors assume no liability for misuse.

## License

MIT — See [LICENSE](LICENSE).
