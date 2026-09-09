import os
from typing import Dict, Any, List
from packet_engine.parser import parse_packet_dict
from packet_engine.rules import RuleEngine

def analyze_pcap_file(filepath: str) -> Dict[str, Any]:
    """
    Reads a .pcap or .pcapng file using Scapy, extracts all packet logs,
    and runs the RuleEngine over the recorded packets.
    """
    results = {
        "total_packets": 0,
        "packets": [],
        "alerts": [],
        "protocols": {},
        "top_ips": {}
    }

    try:
        from scapy.all import rdpcap
        packets = rdpcap(filepath)
    except Exception as e:
        return {"error": f"Failed to read PCAP file: {str(e)}"}

    rule_engine = RuleEngine()

    for idx, pkt in enumerate(packets):
        parsed = parse_packet_dict(pkt)
        if not parsed:
            continue

        parsed["id"] = idx + 1
        results["total_packets"] += 1

        # Protocol stats
        proto = parsed.get("protocol", "OTHER")
        results["protocols"][proto] = results["protocols"].get(proto, 0) + 1

        # Top IP stats
        src = parsed.get("source_ip", "Unknown")
        if src != "Unknown":
            results["top_ips"][src] = results["top_ips"].get(src, 0) + 1

        # Store sample packets (up to 500 max)
        if len(results["packets"]) < 500:
            results["packets"].append(parsed)

        # Run rules
        alerts = rule_engine.inspect(parsed)
        for a in alerts:
            results["alerts"].append(a)

    return results
