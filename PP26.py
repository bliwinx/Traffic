import base64
import csv
import os
import queue
import re
import threading
import time
import traceback
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from scapy.all import sniff, PcapWriter, DNS, DNSQR, IP, IPv6, TCP, UDP, ICMP, ARP, Raw


@dataclass
class TrafficInfo:
    time: float
    src: str
    dst: str
    proto: str
    size: int
    status: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: Optional[str] = None
    dns_name: Optional[str] = None
    reason: Optional[str] = None
    leak_data: Optional[str] = None

#------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklist.txt")
LEAK_FILE = os.path.join(BASE_DIR, "leaks.csv")
PCAP_FILE = os.path.join(BASE_DIR, "http_traffic.pcap")

LEAK_PATTERNS = [
    ("Password sent in plain text",
     re.compile(rb"(?i)\b(password|passwd|pwd|pass)=[^&\s]+")),
    ("Token or API key in plain text",
     re.compile(rb"(?i)\b(token|access_token|api[_-]?key|secret)=[^&\s]+")),
    ("Basic auth header",
     re.compile(rb"(?i)authorization:\s*basic\s+[a-z0-9+/=]+")),
    ("Bearer token header",
     re.compile(rb"(?i)authorization:\s*bearer\s+[\w\-\.]+")),
    ("Session cookie",
     re.compile(rb"(?i)\ncookie:[^\r\n]*(session|sid|auth)[^\r\n]*")),
    ("FTP credentials",
     re.compile(rb"^(USER|PASS) \S+", re.M)),
    ("Email address",
     re.compile(rb"[\w.+-]+@[\w-]+\.[\w.-]+")),
]

CARD_PATTERN = re.compile(rb"\b(?:\d[ -]?){13,16}\b")

PLAIN_PORTS = {80, 8080, 21, 23, 25, 110, 143}

blocklist = set()     
blocked_ips = {}      
block_lock = threading.Lock()

traffic_queue = queue.Queue(maxsize=5000)

last_seen = {}
proto_count = Counter()
leak_lock = threading.Lock()

#------------------------------------------------------------


# http pkts into pcap file
try:
    http_pcap = PcapWriter(PCAP_FILE, append=True, sync=True)
except Exception as error:
    print("Cannot open pcap file:", error)
    http_pcap = None



def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            f.write("# one domain per line\nbadsite.com\n")

    domains = set()
    with open(BLOCKLIST_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                domains.add(line)

    with block_lock:
        blocklist.clear()
        blocklist.update(domains)


def blocked_domain(name):
   #returns domain from blacked list if name matches or none
    if not name:
        return None
    name = name.lower().rstrip(".")
    with block_lock:
        for b in blocklist:
            if name == b or name.endswith("." + b):
                return b
    return None


def learn_ips(pkt):
    #remember ip address of blocked domain from dns response 

    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
        return
    dns = pkt[DNS]
    if dns.qr != 1 or not dns.ancount:
        return

    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    base = blocked_domain(qname)
    if not base:
        return

    for i in range(dns.ancount):
        try:
            rr = dns.an[i]
        except Exception:
            break
        if rr.type in (1, 28):            # A и AAAA
            with block_lock:
                blocked_ips[str(rr.rdata)] = base




def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def check_leak(pkt, dport):
    #returns (type, value) or none. checks only outgoing traffic
 
    if dport not in PLAIN_PORTS or not pkt.haslayer(Raw):
        return None

    data = pkt[Raw].load

    for name, pattern in LEAK_PATTERNS:
        m = pattern.search(data)
        if m:
            text = m.group().decode("latin-1", "replace").strip()
            if name == "Basic auth header":
                try:
                    decoded = base64.b64decode(text.split()[-1]).decode("utf-8", "replace")
                    text = f"Basic {decoded}"   
                except Exception:
                    pass
            return name, text[:200]

    for m in CARD_PATTERN.finditer(data):
        number = m.group().decode("ascii", "ignore")
        if luhn_ok(number):
            return "Possible card number", number

    return None


def parse(pkt):
    #any pkt -> traffic info, unknown -> none

    if pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    elif pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None

    proto, sport, dport, flags = "OTHER", None, None, None
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif pkt.haslayer(ARP):
        proto = "ARP"

    domain = None
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        domain = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")

    learn_ips(pkt)

    base = blocked_domain(domain)
    with block_lock:
        ip_domain = blocked_ips.get(dst) or blocked_ips.get(src)

    # checks on leaks even if traffic is gooing to be blocked 
    leak = check_leak(pkt, dport)
    leak_data = leak[1] if leak else None

    status, reason = "allowed", None
    if base:
        status = "blocked"
        reason = f"Domain in blocklist: {base}"
    elif ip_domain:
        status = "blocked"
        reason = f"IP of blocked domain: {ip_domain}"
    elif leak:
        status = "blocked"
        reason = f"Leak: {leak[0]}"

    if leak and not reason.startswith("Leak"):
        reason += f" (+ leak: {leak[0]})"

    return TrafficInfo(time=float(pkt.time), src=src, dst=dst, proto=proto,
                       size=len(pkt), status=status, sport=sport,
                       dport=dport, flags=flags, dns_name=domain,
                       reason=reason, leak_data=leak_data)


def save_leak(rec):
    try:
        with leak_lock:
            is_new = not os.path.exists(LEAK_FILE)
            with open(LEAK_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if is_new:
                    writer.writerow(["time", "src", "dst", "reason", "data"])
                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.time)),
                    f"{rec.src}:{rec.sport or ''}",
                    f"{rec.dst}:{rec.dport or ''}",
                    rec.reason,
                    rec.leak_data,
                ])
    except OSError as error:
        print("Cannot write leak log:", error)


def save_pcap(pkt):
    if http_pcap is None:
        return
    try:
        http_pcap.write(pkt)
    except Exception as error:
        print("Cannot write pcap:", error)


def handler(pkt):
    try:
        rec = parse(pkt)
        if rec is None:
            return

        if rec.sport == 80 or rec.dport == 80:
            save_pcap(pkt)

        if rec.leak_data:
            save_leak(rec)

        proto_count[rec.proto] += 1

        if rec.sport == 53:
            return

        if rec.dns_name is not None:
            if rec.dns_name in last_seen and rec.time - last_seen[rec.dns_name] < 5:
                return
            last_seen[rec.dns_name] = rec.time



            if len(last_seen) > 5000:
                for key in [k for k, t in last_seen.items() if rec.time - t > 60]:
                    del last_seen[key]

        try:
            traffic_queue.put_nowait(rec)
        except queue.Full:
            pass
    except Exception:
        traceback.print_exc()


def print_stats():
    while True:
        time.sleep(5)
        print(dict(proto_count))


def start_sniffing():
    load_blocklist()
    threading.Thread(
        target=lambda: sniff(filter="ip or ip6 or arp", prn=handler, store=False),
        daemon=True,
    ).start()
    threading.Thread(target=print_stats, daemon=True).start()