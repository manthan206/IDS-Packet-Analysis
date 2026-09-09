import os
import shutil
import asyncio
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import engine, get_db, Base
import models, schemas, auth, reports
from websocket_manager import manager
from middleware import SecurityHeadersMiddleware, SimpleRateLimiterMiddleware
from packet_engine.capture import capture_engine
from packet_engine.pcap_analyzer import analyze_pcap_file
from geoip import get_country_for_ip

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Intrusion Detection System & Packet Analysis API",
    description="Enterprise grade real-time IDS backend powered by FastAPI, Scapy & Machine Learning",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enable Custom Security & Rate Limiting Middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SimpleRateLimiterMiddleware, max_requests=300, window_seconds=60)

# Seed default admin user if not exists
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    admin_user = db.query(models.User).filter(models.User.username == "admin").first()
    if not admin_user:
        hashed_pwd = auth.get_password_hash("admin123")
        db.add(models.User(username="admin", hashed_password=hashed_pwd, role="admin"))
        db.commit()
    
    # Store event loop reference for PacketCaptureEngine
    capture_engine.loop = asyncio.get_event_loop()
    # Auto-start capture engine
    capture_engine.start()

@app.on_event("shutdown")
def shutdown_event():
    capture_engine.stop()

# ----------------- AUTH ENDPOINTS ----------------- #

@app.post("/api/auth/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username, "role": user.role})
    
    # Audit log
    db.add(models.AuditLog(username=user.username, action="USER_LOGIN"))
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }

@app.post("/api/auth/register", response_model=schemas.UserResponse)
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pwd = auth.get_password_hash(user_data.password)
    new_user = models.User(username=user_data.username, hashed_password=hashed_pwd, role=user_data.role or "analyst")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get("/api/auth/me", response_model=schemas.UserResponse)
def get_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user

# ----------------- STATS & DASHBOARD API ----------------- #

@app.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    total_packets = db.query(models.PacketLog).count()
    total_alerts = db.query(models.Alert).count()

    critical_alerts = db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count()
    high_alerts = db.query(models.Alert).filter(models.Alert.severity == "HIGH").count()
    medium_alerts = db.query(models.Alert).filter(models.Alert.severity == "MEDIUM").count()
    low_alerts = db.query(models.Alert).filter(models.Alert.severity == "LOW").count()

    # Protocol Distribution
    proto_query = db.query(models.PacketLog.protocol, func.count(models.PacketLog.id)).group_by(models.PacketLog.protocol).all()
    protocol_distribution = {p[0] or "OTHER": p[1] for p in proto_query}

    # Top Source IPs
    top_src_query = db.query(models.PacketLog.source_ip, func.count(models.PacketLog.id)).group_by(models.PacketLog.source_ip).order_by(func.count(models.PacketLog.id).desc()).limit(5).all()
    top_sources = [{"ip": item[0], "count": item[1], "country": get_country_for_ip(item[0])} for item in top_src_query]

    # Top Dest IPs
    top_dst_query = db.query(models.PacketLog.dest_ip, func.count(models.PacketLog.id)).group_by(models.PacketLog.dest_ip).order_by(func.count(models.PacketLog.id).desc()).limit(5).all()
    top_destinations = [{"ip": item[0], "count": item[1]} for item in top_dst_query]

    engine_status = capture_engine.get_status()

    return {
        "total_packets": total_packets + engine_status["total_packets"],
        "total_alerts": total_alerts + engine_status["total_alerts"],
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "packets_per_second": engine_status["packets_per_second"],
        "bandwidth_kbps": round(engine_status["packets_per_second"] * 0.8, 2),
        "protocol_distribution": protocol_distribution,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "is_capturing": engine_status["is_capturing"]
    }

# ----------------- PACKET LOGS & ALERTS ----------------- #

@app.get("/api/packets")
def get_packets(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    packets = db.query(models.PacketLog).order_by(models.PacketLog.id.desc()).offset(offset).limit(limit).all()
    return packets

@app.get("/api/alerts")
def get_alerts(severity: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    query = db.query(models.Alert)
    if severity and severity.upper() != "ALL":
        query = query.filter(models.Alert.severity == severity.upper())
    alerts = query.order_by(models.Alert.id.desc()).limit(limit).all()
    return alerts

@app.put("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    db.commit()
    return {"message": "Alert acknowledged"}

# ----------------- PCAP UPLOAD & ANALYSIS ----------------- #

@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...), current_user: models.User = Depends(auth.get_current_user)):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")
    
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, file.filename)

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    analysis_results = analyze_pcap_file(filepath)
    return analysis_results

# ----------------- NETWORK TOPOLOGY API ----------------- #

@app.get("/api/topology")
def get_network_topology(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    packets = db.query(models.PacketLog).order_by(models.PacketLog.id.desc()).limit(200).all()
    nodes_map = {}
    links = []

    for pkt in packets:
        src = pkt.source_ip or "Unknown"
        dst = pkt.dest_ip or "Unknown"
        
        if src not in nodes_map:
            nodes_map[src] = {"id": src, "group": 1 if "192.168" in src or "10.0" in src else 2}
        if dst not in nodes_map:
            nodes_map[dst] = {"id": dst, "group": 1 if "192.168" in dst or "10.0" in dst else 2}

        links.append({"source": src, "target": dst, "value": 1, "protocol": pkt.protocol})

    return {
        "nodes": list(nodes_map.values()),
        "links": links[:150]
    }

# ----------------- CAPTURE CONTROL ----------------- #

@app.post("/api/capture/start")
def start_capture(config: schemas.CaptureFilterSchema, current_user: models.User = Depends(auth.require_admin)):
    capture_engine.start(interface=config.interface or "all", bpf_filter=config.bpf_filter or "")
    return {"message": "Packet capture started", "status": capture_engine.get_status()}

@app.post("/api/capture/stop")
def stop_capture(current_user: models.User = Depends(auth.require_admin)):
    capture_engine.stop()
    return {"message": "Packet capture stopped", "status": capture_engine.get_status()}

# ----------------- SECURITY REPORTS & EXPORTS ----------------- #

@app.get("/api/reports/pdf")
def export_pdf_report(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    pdf_buffer = reports.generate_pdf_report(db)
    filename = f"cybersentinel_security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ----------------- WEBSOCKET STREAMING ----------------- #

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ----------------- FRONTEND MOUNTING ----------------- #

frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
