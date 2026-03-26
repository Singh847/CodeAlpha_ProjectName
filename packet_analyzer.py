#!/usr/bin/env python3
"""
============================================================
  Network Traffic Packet Analyzer
  Uses: scapy (primary) with socket fallback
  Displays: Source/Dest IPs, Protocols, Payloads & more
============================================================
"""

import sys
import time
import signal
import argparse
from datetime import datetime
from collections import defaultdict

# ── Try importing Scapy ──────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP,
        Raw, Ether, get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Fallback: raw socket capture ────────────────────────
import socket
import struct


# ════════════════════════════════════════════════════════
#  ANSI colour helpers
# ════════════════════════════════════════════════════════
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

def colour(text, *codes):
    return "".join(codes) + str(text) + RESET

def banner():
    print(colour("""
╔══════════════════════════════════════════════════════════╗
║        🔍  Network Traffic Packet Analyzer               ║
║            Capture · Analyse · Understand                ║
╚══════════════════════════════════════════════════════════╝
""", CYAN, BOLD))


# ════════════════════════════════════════════════════════
#  Statistics tracker
# ════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self.total       = 0
        self.by_proto    = defaultdict(int)
        self.by_src      = defaultdict(int)
        self.by_dst      = defaultdict(int)
        self.start_time  = time.time()
        self.bytes_total = 0

    def record(self, proto, src, dst, size):
        self.total          += 1
        self.by_proto[proto]+= 1
        self.by_src[src]    += 1
        self.by_dst[dst]    += 1
        self.bytes_total    += size

    def summary(self):
        elapsed = time.time() - self.start_time
        print(colour("\n╔══════════════  SESSION SUMMARY  ══════════════╗", CYAN, BOLD))
        print(colour(f"  Duration      : {elapsed:.1f} s", WHITE))
        print(colour(f"  Total Packets : {self.total}", WHITE))
        print(colour(f"  Total Bytes   : {self.bytes_total:,}", WHITE))

        print(colour("\n  ── By Protocol ──", YELLOW, BOLD))
        for p, c in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            bar = "█" * min(c, 40)
            print(f"    {colour(p.ljust(8), GREEN)} {bar}  {c}")

        print(colour("\n  ── Top 5 Sources ──", YELLOW, BOLD))
        for ip, c in sorted(self.by_src.items(), key=lambda x: -x[1])[:5]:
            print(f"    {colour(ip.ljust(20), CYAN)}  {c} pkts")

        print(colour("\n  ── Top 5 Destinations ──", YELLOW, BOLD))
        for ip, c in sorted(self.by_dst.items(), key=lambda x: -x[1])[:5]:
            print(f"    {colour(ip.ljust(20), MAGENTA)}  {c} pkts")

        print(colour("╚═══════════════════════════════════════════════╝\n", CYAN, BOLD))


stats = Stats()


# ════════════════════════════════════════════════════════
#  Protocol helpers
# ════════════════════════════════════════════════════════
PROTO_NAMES = {
    1:  "ICMP", 6:  "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 58: "ICMPv6",
    89: "OSPF", 132:"SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP",     53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP",    110: "POP3",143: "IMAP",161:"SNMP",
    443:"HTTPS",   445:"SMB", 3306:"MySQL",5432:"PostgreSQL",
    6379:"Redis",  8080:"HTTP-alt",
}

def port_label(port):
    return WELL_KNOWN_PORTS.get(port, str(port))

def proto_colour(name):
    colours = {
        "TCP": GREEN, "UDP": CYAN, "ICMP": YELLOW,
        "DNS": MAGENTA, "ARP": BLUE, "HTTP": RED,
        "HTTPS": RED, "OTHER": WHITE,
    }
    return colours.get(name, WHITE)


# ════════════════════════════════════════════════════════
#  Packet display
# ════════════════════════════════════════════════════════
PKT_COUNT = [0]

def fmt_payload(raw_bytes, max_bytes=64):
    """Return a human-readable snippet of payload."""
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_bytes]
    # Try UTF-8 printable
    try:
        text = snippet.decode("utf-8", errors="strict")
        printable = "".join(c if c.isprintable() else "." for c in text)
        return f'"{printable[:80]}"'
    except Exception:
        pass
    # Hex dump
    hexpart  = " ".join(f"{b:02x}" for b in snippet)
    charpart = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
    return f"HEX: {hexpart}  |  {charpart}"


def print_packet(ts, proto, src, dst, extra, payload, size):
    PKT_COUNT[0] += 1
    pc = colour(f"#{PKT_COUNT[0]:05d}", DIM)
    t  = colour(ts, DIM)
    p  = colour(f"[{proto:>6}]", proto_colour(proto), BOLD)
    arrow = colour("→", DIM)

    print(f"\n{pc} {t}  {p}")
    print(f"  {colour('SRC', CYAN, BOLD)} {colour(src, CYAN)}  {arrow}  {colour('DST', MAGENTA, BOLD)} {colour(dst, MAGENTA)}")
    if extra:
        print(f"  {colour('INFO', YELLOW)}  {extra}")
    if payload:
        print(f"  {colour('DATA', DIM)}  {colour(payload, DIM)}")
    print(f"  {colour('SIZE', DIM)}  {size} bytes")
    print(colour("  " + "─" * 60, DIM))

    stats.record(proto, src.split(":")[0], dst.split(":")[0], size)


# ════════════════════════════════════════════════════════
#  Scapy packet callback
# ════════════════════════════════════════════════════════
def scapy_callback(pkt, show_payload=True):
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size  = len(pkt)
    proto = "OTHER"
    src = dst = "?"
    extra = ""
    payload = ""

    # ── ARP ────────────────────────────────────────────
    if ARP in pkt:
        a = pkt[ARP]
        proto = "ARP"
        src, dst = a.psrc, a.pdst
        op = "REQUEST" if a.op == 1 else "REPLY"
        extra = f"ARP {op}  {colour(a.hwsrc, DIM)} → {colour(a.hwdst, DIM)}"

    # ── IPv4 ───────────────────────────────────────────
    elif IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto_num = ip.proto

        if TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.sprintf("%flags%")
            sport, dport = tcp.sport, tcp.dport
            service = port_label(dport) or port_label(sport)
            proto = service if service in ("HTTP","HTTPS","FTP","SSH",
                                           "SMTP","DNS") else "TCP"
            src = f"{ip.src}:{sport}"
            dst = f"{ip.dst}:{dport}"
            extra = (f"Flags={colour(flags,YELLOW)}  "
                     f"Seq={tcp.seq}  Ack={tcp.ack}  "
                     f"Win={tcp.window}  "
                     f"Sport={colour(port_label(sport),GREEN)}  "
                     f"Dport={colour(port_label(dport),GREEN)}")

        elif UDP in pkt:
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            proto = "DNS" if (dport == 53 or sport == 53) else "UDP"
            src = f"{ip.src}:{sport}"
            dst = f"{ip.dst}:{dport}"
            extra = (f"Sport={colour(port_label(sport),GREEN)}  "
                     f"Dport={colour(port_label(dport),GREEN)}  "
                     f"Len={udp.len}")
            # DNS details
            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:
                    extra += f"  QUERY={colour(dns.qd.qname.decode(),CYAN)}"
                elif dns.qr == 1 and dns.an:
                    extra += f"  ANSWER={colour(str(dns.an.rdata),MAGENTA)}"

        elif ICMP in pkt:
            ic = pkt[ICMP]
            proto = "ICMP"
            t_map = {0:"Echo Reply", 3:"Dest Unreachable",
                     8:"Echo Request", 11:"Time Exceeded"}
            extra = f"Type={ic.type} ({t_map.get(ic.type,'?')})  Code={ic.code}"

        else:
            proto = PROTO_NAMES.get(proto_num, f"IP/{proto_num}")

    # ── IPv6 ───────────────────────────────────────────
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
        proto = "IPv6"
        extra = f"NH={ip6.nh}  HopLimit={ip6.hlim}"

    else:
        # Unknown / Layer-2 only
        if Ether in pkt:
            eth = pkt[Ether]
            src, dst = eth.src, eth.dst
            proto = f"ETH/0x{eth.type:04x}"
        return   # skip non-IP noise unless you want L2

    # ── Payload ────────────────────────────────────────
    if show_payload and Raw in pkt:
        payload = fmt_payload(bytes(pkt[Raw]))

    print_packet(ts, proto, src, dst, extra, payload, size)


# ════════════════════════════════════════════════════════
#  Raw-socket fallback (Linux only, no Scapy)
# ════════════════════════════════════════════════════════
def raw_socket_capture(count=0, show_payload=True):
    """Basic capture using raw sockets – Linux only."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(0x0003))
    except PermissionError:
        print(colour("  ✖  Root/admin privileges required for raw sockets.", RED, BOLD))
        sys.exit(1)
    except AttributeError:
        print(colour("  ✖  AF_PACKET not available (Windows/macOS). "
                     "Please install scapy.", RED, BOLD))
        sys.exit(1)

    n = 0
    while True:
        raw, _ = sock.recvfrom(65535)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        size = len(raw)

        # Ethernet header (14 bytes)
        if len(raw) < 14:
            continue
        eth_proto = struct.unpack("!H", raw[12:14])[0]

        if eth_proto != 0x0800:   # Only IPv4 for simplicity
            continue

        ip_header = raw[14:34]
        if len(ip_header) < 20:
            continue
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        proto_num = iph[6]
        src_ip    = socket.inet_ntoa(iph[8])
        dst_ip    = socket.inet_ntoa(iph[9])
        ihl       = (iph[0] & 0xF) * 4

        proto = PROTO_NAMES.get(proto_num, f"IP/{proto_num}")
        src, dst = src_ip, dst_ip
        extra = ""
        payload = ""

        transport = raw[14 + ihl:]

        if proto_num == 6 and len(transport) >= 20:   # TCP
            th = struct.unpack("!HHLLBBHHH", transport[:20])
            sport, dport = th[0], th[1]
            flags_raw = th[5]
            flag_str  = "".join([
                "F" if flags_raw & 0x01 else "",
                "S" if flags_raw & 0x02 else "",
                "R" if flags_raw & 0x04 else "",
                "P" if flags_raw & 0x08 else "",
                "A" if flags_raw & 0x10 else "",
            ])
            src = f"{src_ip}:{sport}"
            dst = f"{dst_ip}:{dport}"
            proto = "TCP"
            extra = (f"Flags={colour(flag_str,YELLOW)}  "
                     f"Sport={colour(port_label(sport),GREEN)}  "
                     f"Dport={colour(port_label(dport),GREEN)}")
            data_off = ((transport[12] >> 4) * 4)
            if show_payload:
                payload = fmt_payload(transport[data_off:data_off+64])

        elif proto_num == 17 and len(transport) >= 8:  # UDP
            sport, dport = struct.unpack("!HH", transport[:4])
            src = f"{src_ip}:{sport}"
            dst = f"{dst_ip}:{dport}"
            proto = "UDP"
            extra = (f"Sport={colour(port_label(sport),GREEN)}  "
                     f"Dport={colour(port_label(dport),GREEN)}")
            if show_payload:
                payload = fmt_payload(transport[8:72])

        elif proto_num == 1 and len(transport) >= 4:   # ICMP
            icmp_type, icmp_code = transport[0], transport[1]
            proto = "ICMP"
            t_map = {0:"Echo Reply", 8:"Echo Request"}
            extra = f"Type={icmp_type} ({t_map.get(icmp_type,'?')})  Code={icmp_code}"

        print_packet(ts, proto, src, dst, extra, payload, size)

        n += 1
        if count and n >= count:
            break

    sock.close()


# ════════════════════════════════════════════════════════
#  Interface listing
# ════════════════════════════════════════════════════════
def list_interfaces():
    print(colour("\n  Available network interfaces:", CYAN, BOLD))
    if SCAPY_AVAILABLE:
        for iface in get_if_list():
            print(f"    • {colour(iface, GREEN)}")
    else:
        for name, info in socket.if_nameindex():
            print(f"    • {colour(info, GREEN)}")
    print()


# ════════════════════════════════════════════════════════
#  Graceful shutdown
# ════════════════════════════════════════════════════════
def handle_signal(sig, frame):
    print(colour("\n\n  [!] Capture stopped by user (Ctrl+C)\n", YELLOW, BOLD))
    stats.summary()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)


# ════════════════════════════════════════════════════════
#  CLI entry-point
# ════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        description="Network Packet Analyzer — scapy / raw-socket",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_analyzer.py
  sudo python3 packet_analyzer.py -i eth0 -c 50
  sudo python3 packet_analyzer.py -f "tcp port 80" -v
  sudo python3 packet_analyzer.py --list-interfaces
        """
    )
    p.add_argument("-i", "--iface",   default=None,
                   help="Interface to sniff on (default: auto)")
    p.add_argument("-c", "--count",   type=int, default=0,
                   help="Stop after N packets (0 = unlimited)")
    p.add_argument("-f", "--filter",  default="",
                   help="BPF filter string (scapy only, e.g. 'tcp port 80')")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show packet payload data")
    p.add_argument("--list-interfaces", action="store_true",
                   help="Print available interfaces and exit")
    p.add_argument("--no-colour", action="store_true",
                   help="Disable ANSI colours")
    return p.parse_args()


def main():
    args = parse_args()

    if args.no_colour:
        # Blank out all colour codes
        for name in ["RESET","BOLD","RED","GREEN","YELLOW",
                     "CYAN","BLUE","MAGENTA","WHITE","DIM"]:
            globals()[name] = ""

    banner()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # ── Backend selection ──────────────────────────────
    if SCAPY_AVAILABLE:
        print(colour("  ✔  Scapy detected — using full packet dissection\n", GREEN, BOLD))
        print(colour("  ◉  Capture started — press Ctrl+C to stop\n", YELLOW))

        iface_kwarg = {"iface": args.iface} if args.iface else {}
        sniff(
            prn=lambda p: scapy_callback(p, show_payload=args.verbose),
            filter=args.filter,
            count=args.count,
            store=False,
            **iface_kwarg,
        )
    else:
        print(colour("  ⚠  Scapy not found — falling back to raw sockets\n", YELLOW, BOLD))
        print(colour("     Install scapy for full protocol support:  pip install scapy\n", DIM))
        print(colour("  ◉  Capture started (IPv4 only) — press Ctrl+C to stop\n", YELLOW))
        raw_socket_capture(count=args.count, show_payload=args.verbose)

    stats.summary()


if __name__ == "__main__":
    main()
