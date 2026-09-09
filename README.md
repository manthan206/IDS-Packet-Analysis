# 🛡️ CyberSentinel — Production-Grade Intrusion Detection & Packet Analysis System

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://www.python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-00f2fe?style=flat-square)](https://scapy.net)
[![ReportLab](https://img.shields.io/badge/ReportLab-PDF-red?style=flat-square)](https://www.reportlab.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

**CyberSentinel** is a full-stack, enterprise-grade Intrusion Detection System (IDS) and Network Packet Analysis platform built for 24/7 continuous operation. It features live packet sniffing (via Scapy & raw sockets), real active system socket connection monitoring (`psutil`), a hybrid behavioral/signature detection rule engine, statistical Z-score anomaly detection, an offline PCAP analyzer, real-time D3.js network topology graphs, GeoIP location resolution, automated PDF security report generation, and a responsive glassmorphism dark dashboard powered by WebSockets.

---

## 🌟 Key Features & Architectural Highlights

- **24/7 Dual-Engine Packet Capture Pipeline**:
  - **Live Adapter Sniffing**: Uses Scapy and raw sockets for real-time physical interface packet sniffing (`eth0` / `Wi-Fi`).
  - **Real System Sockets**: Monitors real active socket connections directly from the host operating system (`psutil`).
  - **Synthetic Threat Injector**: Injects simulated attack vectors (Port Scans, SYN Floods, SQLi, Brute Force) ensuring a 24/7 working demo for resume presentations.
- **Hybrid Threat Detection Rules**:
  - **Behavioral & Signature Engine**: 10+ attack rules detecting Port Scans, SYN Floods, SSH/FTP Brute Force, ICMP Floods, Ping of Death, XMAS Scans, NULL Scans, SQL Injection patterns, XSS payloads, and DNS Tunneling.
  - **Statistical Anomaly Detection**: Evaluates packet size distributions and arrival intervals using Z-scores (>4.5 std dev) to flag zero-day traffic anomalies.
- **Valid & Accurate GeoIP Region Engine**:
  - Resolves exact **City**, **Region / State**, **Country**, and **ISO Country Flag Emojis** (e.g. `Vadodara, Gujarat, India 🇮🇳`, `Fremont, California, United States 🇺🇸`).
  - Auto-detects local host operating system region for internal traffic.
- **Automated PDF Security Report Generator**:
  - Integrated `ReportLab` engine exporting signed PDF forensic reports (`/api/reports/pdf`) compiling total metrics, threat severity breakdown, top attacker origin tables, and incident audit logs.
- **Interactive D3.js Network Topology Map**:
  - Real-time force-directed node graph visualizing active IP connections and protocol traffic flow lines.
- **Offline PCAP Analyzer**:
  - Drag-and-drop `.pcap` / `.pcapng` file upload scanner for deep offline packet inspection and vulnerability identification.
- **Responsive Auto-Adjusting Glassmorphic UI**:
  - Adapts to Desktops, Laptops, Tablets, and Mobile phones with off-canvas hamburger navigation.
- **Enterprise Security Mechanisms**:
  - JWT Authentication (`HS256` token expiration & hashing)
  - Rate Limiting Middleware (300 requests/min per IP)
  - Security Headers Middleware (CSP, HSTS, X-Frame-Options, XSS protection)
  - Role-Based Access Control (`admin` vs `analyst`)

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FRONTEND (Browser)                      │
│   HTML5 + CSS Glassmorphism + ApexCharts + D3.js + WebSockets│
└────────────────────┬────────────────────────────────────────┘
                     │  REST API (JWT) / WebSocket Stream (/ws)
┌────────────────────▼────────────────────────────────────────┐
│                  FASTAPI BACKEND ENGINE                     │
│   Security Headers · Rate Limiter · OAuth2 JWT Auth         │
└──────────┬─────────────────────────────┬────────────────────┘
           │                             │
┌──────────▼──────────┐      ┌──────────▼──────────────────┐
│  PACKET ENGINE       │      │  PERSISTENCE & REPORTING    │
│  - Scapy Sniffer    │      │  - SQLite (SQLAlchemy)       │
│  - Real Sockets     │      │  - GeoIP Region Lookup       │
│  - 10+ Threat Rules │      │  - ReportLab PDF Engine     │
│  - Anomaly Detector │      │  - Audit Logs & Users       │
└─────────────────────┘      └─────────────────────────────┘
```

---

## 📂 Project Directory Structure

```
ids-project/
├── backend/
│   ├── main.py                 # FastAPI application & REST/WebSocket routes
│   ├── auth.py                 # JWT authentication & password hashing
│   ├── database.py             # SQLAlchemy database setup
│   ├── models.py               # Database schemas (PacketLog, Alert, User, AuditLog)
│   ├── schemas.py              # Pydantic data schemas
│   ├── geoip.py                # GeoIP region resolution engine
│   ├── reports.py              # ReportLab PDF security report generator
│   ├── middleware.py           # Rate limiting & security headers middleware
│   ├── websocket_manager.py    # Real-time WebSocket connection manager
│   ├── packet_engine/
│   │   ├── capture.py          # Dual-mode 24/7 packet capture worker
│   │   ├── parser.py           # Scapy packet layer parser
│   │   ├── rules.py            # Signature & behavioral threat rules
│   │   ├── anomaly.py          # Statistical Z-score anomaly detector
│   │   └── pcap_analyzer.py    # Offline PCAP file inspector
│   └── requirements.txt        # Backend dependencies
├── frontend/
│   ├── index.html              # Single Page Application HTML layout
│   ├── css/
│   │   └── style.css           # Responsive glassmorphism CSS design system
│   └── js/
│       ├── api.js              # REST & PDF download client wrapper
│       ├── app.js              # Routing, auth modal & WebSocket controller
│       ├── dashboard.js        # ApexCharts streaming line & donut graphs
│       ├── packets.js          # Live packet table & search filters
│       ├── alerts.js           # Security threat alerts & acknowledge action
│       ├── topology.js         # D3.js force-directed network topology graph
│       ├── analysis.js         # PCAP file drag-and-drop handler
│       └── settings.js         # Capture engine configuration controls
├── docker-compose.yml          # Container orchestration spec
├── Dockerfile                  # Container build file
└── README.md                   # System documentation
```

---

## 🚀 Quick Start Guide

### Option 1: Run Locally with Python

1. **Navigate to the backend directory**:
   ```bash
   cd ids-project/backend
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the FastAPI server**:
   ```bash
   python -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```

4. **Access the Dashboard**:
   Open your web browser and navigate to `http://127.0.0.1:8000`.
   - **Default Admin Username**: `admin`
   - **Default Admin Password**: `admin123`

---

### Option 2: Run with Docker Compose (Recommended for 24/7 Server Deployment)

```bash
docker-compose up --build -d
```

The container runs with `NET_ADMIN` and `NET_RAW` Linux capabilities to capture physical interface traffic continuously.

---

## 📊 Dashboard Views

| View | Description |
|------|-------------|
| **Dashboard** | Real-time packet rate sparklines, protocol donut charts, threat ticker, KPI cards, top talkers with GeoIP flags |
| **Live Packets** | Searchable, protocol-filterable live packet table with pause/resume controls |
| **Threat Alerts** | Security alerts feed filtered by severity (Critical, High, Medium, Low) with 1-click acknowledge action |
| **PCAP Analysis** | Drag-and-drop upload zone for offline `.pcap` inspection and threat scanning |
| **Network Topology** | D3.js force-directed node graph showing IP relationships and active streams |
| **Security Reports** | Executive security report overview with 1-click **Download PDF Security Report** |
| **System Settings** | Network interface selector, BPF filter config, and engine start/stop controls |

---

## 🔒 Security Threat Rules Implemented

1. `PORT_SCAN_DETECTED`: Triggered when a single source host probes 10+ distinct ports within 10 seconds.
2. `SYN_FLOOD_DOS`: Triggered when >30 SYN packets arrive targeting a destination host within 2 seconds.
3. `SSH_BRUTE_FORCE` / `FTP_BRUTE_FORCE`: Triggered on 6+ connection attempts on port 22/21 within 15 seconds.
4. `TCP_NULL_SCAN` & `TCP_XMAS_SCAN`: Flags stealth TCP flag combinations (`flags == 0` or `FIN+PSH+URG`).
5. `PING_OF_DEATH` & `ICMP_FLOOD`: Oversized ICMP packets (>1000 Bytes) or ICMP request floods.
6. `SQL_INJECTION_ATTEMPT`: Regex payload match for patterns like `UNION SELECT`, `OR 1=1`, `DROP TABLE`.
7. `XSS_ATTACK_ATTEMPT`: Matches `<script>`, `javascript:`, and event handler injections in payload snippets.
8. `DNS_TUNNELING_EXFIL`: Flags oversized DNS query payloads (>500 Bytes).
9. `STATISTICAL_TRAFFIC_ANOMALY`: Z-score evaluation (>4.5 standard deviations) against historical mean packet size.

---

## 📡 API Endpoints Reference

### Authentication
- `POST /api/auth/login` — Login & receive JWT access token.
- `POST /api/auth/register` — Register a new user.
- `GET /api/auth/me` — Fetch current user profile.

### Dashboard & Analytics
- `GET /api/stats` — Fetch aggregated metrics (PPS, alerts breakdown, protocols, top talkers).
- `GET /api/packets?limit=100` — Fetch paginated packet capture logs.
- `GET /api/alerts?severity=CRITICAL` — Fetch threat alerts filtered by severity.
- `PUT /api/alerts/{id}/acknowledge` — Mark alert as acknowledged.

### PCAP, Topology & Reports
- `POST /api/pcap/upload` — Upload a `.pcap` file for offline analysis.
- `GET /api/topology` — Fetch D3.js node-link topology network JSON.
- `GET /api/reports/pdf` — Stream downloadable PDF security report (`application/pdf`).

### Engine Control
- `POST /api/capture/start` — Start packet capture with custom interface and BPF filter.
- `POST /api/capture/stop` — Stop packet capture.

---

## 📜 License

Distributed under the MIT License. Developed for cybersecurity portfolios, network engineering research, and resume projects.
