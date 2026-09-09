import time
import re
from typing import Dict, Any, List, Optional
from geoip import get_country_for_ip

class RuleEngine:
    def __init__(self):
        # State tracking for behavioral rules
        self.port_scan_tracker: Dict[str, Dict[str, Any]] = {} # src_ip -> {ports: set(), last_seen: float}
        self.syn_flood_tracker: Dict[str, Dict[str, Any]] = {} # dst_ip -> {count: int, start_time: float}
        self.brute_force_tracker: Dict[str, Dict[str, Any]] = {} # src_ip -> {attempts: int, start_time: float}
        self.icmp_rate_tracker: Dict[str, Dict[str, Any]] = {} # src_ip -> {count: int, start_time: float}
        self.arp_ip_mac_table: Dict[str, str] = {} # ip -> mac

    def inspect(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        now = time.time()

        src_ip = pkt.get("source_ip", "")
        dst_ip = pkt.get("dest_ip", "")
        src_port = pkt.get("source_port")
        dst_port = pkt.get("dest_port")
        protocol = pkt.get("protocol", "")
        flags = pkt.get("flags", "")
        payload = pkt.get("payload_snippet", "")
        length = pkt.get("length", 0)

        # 1. NULL Scan Detection (TCP flags = 0 or empty)
        if protocol == "TCP" and (flags == "" or flags == "0" or flags == "F"): # Sometimes represented as 0
            alerts.append(self._create_alert(
                rule_name="TCP_NULL_SCAN",
                severity="HIGH",
                pkt=pkt,
                description=f"Stealth NULL scan detected from {src_ip} targeting port {dst_port}"
            ))

        # 2. XMAS Scan Detection (FIN + PSH + URG flags)
        if protocol == "TCP" and ("F" in flags and "P" in flags and "U" in flags):
            alerts.append(self._create_alert(
                rule_name="TCP_XMAS_SCAN",
                severity="HIGH",
                pkt=pkt,
                description=f"XMAS scan (FIN/PSH/URG flags set) detected from {src_ip} to port {dst_port}"
            ))

        # 3. Port Scan Detection (>10 distinct ports scanned within 10 seconds)
        if src_ip and src_ip != "Unknown" and dst_port:
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {"ports": set(), "last_seen": now}
            
            tracker = self.port_scan_tracker[src_ip]
            if now - tracker["last_seen"] > 10:
                tracker["ports"] = set()
                tracker["last_seen"] = now
            
            tracker["ports"].add(dst_port)
            if len(tracker["ports"]) >= 10:
                alerts.append(self._create_alert(
                    rule_name="PORT_SCAN_DETECTED",
                    severity="CRITICAL",
                    pkt=pkt,
                    description=f"Port scan attempt: Host {src_ip} probed {len(tracker['ports'])} distinct ports in under 10 seconds"
                ))
                tracker["ports"].clear() # Reset to avoid alert storm

        # 4. SYN Flood Detection (>40 SYN packets/sec to a target)
        if protocol == "TCP" and "S" in flags and "A" not in flags:
            if dst_ip not in self.syn_flood_tracker:
                self.syn_flood_tracker[dst_ip] = {"count": 0, "start_time": now}
            
            syn_track = self.syn_flood_tracker[dst_ip]
            if now - syn_track["start_time"] > 2.0:
                syn_track["count"] = 0
                syn_track["start_time"] = now
            
            syn_track["count"] += 1
            if syn_track["count"] > 30:
                alerts.append(self._create_alert(
                    rule_name="SYN_FLOOD_DOS",
                    severity="CRITICAL",
                    pkt=pkt,
                    description=f"Potential SYN Flood DoS attack targeting {dst_ip} ({syn_track['count']} SYN pkts in 2s)"
                ))
                syn_track["count"] = 0

        # 5. SSH / FTP Brute Force Attempt (High frequency traffic on port 22/21)
        if dst_port in (22, 21):
            if src_ip not in self.brute_force_tracker:
                self.brute_force_tracker[src_ip] = {"attempts": 0, "start_time": now}
            
            bf_track = self.brute_force_tracker[src_ip]
            if now - bf_track["start_time"] > 15.0:
                bf_track["attempts"] = 0
                bf_track["start_time"] = now
            
            bf_track["attempts"] += 1
            if bf_track["attempts"] >= 6:
                service = "SSH" if dst_port == 22 else "FTP"
                alerts.append(self._create_alert(
                    rule_name=f"{service}_BRUTE_FORCE",
                    severity="HIGH",
                    pkt=pkt,
                    description=f"Possible {service} brute-force attack from {src_ip} ({bf_track['attempts']} connection attempts)"
                ))
                bf_track["attempts"] = 0

        # 6. ICMP Flood / Ping of Death
        if protocol == "ICMP":
            if length > 1000:
                alerts.append(self._create_alert(
                    rule_name="PING_OF_DEATH",
                    severity="HIGH",
                    pkt=pkt,
                    description=f"Oversized ICMP packet ({length} bytes) detected from {src_ip}"
                ))
            
            if src_ip not in self.icmp_rate_tracker:
                self.icmp_rate_tracker[src_ip] = {"count": 0, "start_time": now}
            
            icmp_track = self.icmp_rate_tracker[src_ip]
            if now - icmp_track["start_time"] > 2.0:
                icmp_track["count"] = 0
                icmp_track["start_time"] = now
            
            icmp_track["count"] += 1
            if icmp_track["count"] > 25:
                alerts.append(self._create_alert(
                    rule_name="ICMP_FLOOD",
                    severity="MEDIUM",
                    pkt=pkt,
                    description=f"ICMP Flood detected: {src_ip} sent {icmp_track['count']} ping requests in 2 seconds"
                ))
                icmp_track["count"] = 0

        # 7. SQL Injection Pattern in Payload
        if payload:
            sqli_patterns = [r"UNION\s+SELECT", r"OR\s+1=1", r"DROP\s+TABLE", r"SELECT\s+\*\s+FROM", r"--\s*$"]
            for pattern in sqli_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    alerts.append(self._create_alert(
                        rule_name="SQL_INJECTION_ATTEMPT",
                        severity="CRITICAL",
                        pkt=pkt,
                        description=f"SQL Injection payload pattern detected in traffic from {src_ip}"
                    ))
                    break

        # 8. Cross-Site Scripting (XSS) Pattern in Payload
        if payload:
            xss_patterns = [r"<script>", r"javascript:", r"onerror\s*=", r"onload\s*="]
            for pattern in xss_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    alerts.append(self._create_alert(
                        rule_name="XSS_ATTACK_ATTEMPT",
                        severity="HIGH",
                        pkt=pkt,
                        description=f"Cross-Site Scripting (XSS) payload attempt detected from {src_ip}"
                    ))
                    break

        # 9. DNS Tunneling / Exfiltration (Excessively long DNS queries)
        if protocol == "DNS" and length > 500:
            alerts.append(self._create_alert(
                rule_name="DNS_TUNNELING_EXFIL",
                severity="HIGH",
                pkt=pkt,
                description=f"Suspiciously large DNS payload ({length} bytes) potential DNS tunneling/exfiltration"
            ))

        return alerts

    def _create_alert(self, rule_name: str, severity: str, pkt: Dict[str, Any], description: str) -> Dict[str, Any]:
        src_ip = pkt.get("source_ip", "Unknown")
        country = get_country_for_ip(src_ip)
        return {
            "rule_name": rule_name,
            "severity": severity,
            "source_ip": src_ip,
            "dest_ip": pkt.get("dest_ip", "Unknown"),
            "source_port": pkt.get("source_port"),
            "dest_port": pkt.get("dest_port"),
            "protocol": pkt.get("protocol", "OTHER"),
            "description": description,
            "payload_snippet": pkt.get("payload_snippet", "")[:150],
            "country": country,
            "acknowledged": False
        }

rule_engine = RuleEngine()
