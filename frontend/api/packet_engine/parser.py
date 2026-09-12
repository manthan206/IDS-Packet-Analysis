from datetime import datetime
from typing import Dict, Any, Optional

def parse_packet_dict(pkt_raw: Any) -> Optional[Dict[str, Any]]:
    """
    Safely parses a Scapy packet object or dict into a standard structure.
    """
    if isinstance(pkt_raw, dict):
        return pkt_raw

    try:
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

        timestamp = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        length = len(pkt_raw)
        src_ip = "Unknown"
        dst_ip = "Unknown"
        src_port = None
        dst_port = None
        protocol = "OTHER"
        flags_str = ""
        info = ""
        payload_snippet = ""

        if pkt_raw.haslayer(IP):
            src_ip = pkt_raw[IP].src
            dst_ip = pkt_raw[IP].dst
            protocol = "IP"
        elif pkt_raw.haslayer(IPv6):
            src_ip = pkt_raw[IPv6].src
            dst_ip = pkt_raw[IPv6].dst
            protocol = "IPv6"
        elif pkt_raw.haslayer(ARP):
            src_ip = pkt_raw[ARP].psrc
            dst_ip = pkt_raw[ARP].pdst
            protocol = "ARP"
            info = f"ARP Op: {pkt_raw[ARP].op} ({pkt_raw[ARP].hwsrc} -> {pkt_raw[ARP].hwdst})"

        if pkt_raw.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt_raw[TCP].sport
            dst_port = pkt_raw[TCP].dport
            flags = pkt_raw[TCP].flags
            flags_str = str(flags)
            info = f"Seq={pkt_raw[TCP].seq} Ack={pkt_raw[TCP].ack} Flags=[{flags_str}] Win={pkt_raw[TCP].window}"

            if dst_port == 80 or src_port == 80:
                protocol = "HTTP"
            elif dst_port == 443 or src_port == 443:
                protocol = "HTTPS"
            elif dst_port == 22 or src_port == 22:
                protocol = "SSH"

        elif pkt_raw.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt_raw[UDP].sport
            dst_port = pkt_raw[UDP].dport
            info = f"Len={pkt_raw[UDP].len}"

            if pkt_raw.haslayer(DNS):
                protocol = "DNS"
                dns_layer = pkt_raw[DNS]
                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore') if dns_layer.qd else ""
                info = f"DNS Query: {qname}"

        elif pkt_raw.haslayer(ICMP):
            protocol = "ICMP"
            info = f"Type={pkt_raw[ICMP].type} Code={pkt_raw[ICMP].code}"

        if pkt_raw.haslayer(Raw):
            try:
                raw_bytes = bytes(pkt_raw[Raw].load)
                payload_snippet = raw_bytes[:100].decode('latin-1', errors='ignore')
            except Exception:
                payload_snippet = "<binary payload>"

        return {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "protocol": protocol,
            "length": length,
            "flags": flags_str,
            "info": info,
            "payload_snippet": payload_snippet
        }
    except Exception as e:
        return None
