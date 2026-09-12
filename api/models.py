from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst") # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    rule_name = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String)
    description = Column(Text)
    payload_snippet = Column(Text, nullable=True)
    acknowledged = Column(Boolean, default=False)
    country = Column(String, default="Unknown")

class PacketLog(Base):
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True)
    length = Column(Integer)
    flags = Column(String, nullable=True)
    info = Column(String, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    username = Column(String, nullable=False)
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    value = Column(String)
