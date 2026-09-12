from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    username: str
    role: Optional[str] = "analyst"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None

class PacketSchema(BaseModel):
    id: Optional[int] = None
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str
    length: int
    flags: Optional[str] = ""
    info: Optional[str] = ""

class AlertSchema(BaseModel):
    id: Optional[int] = None
    timestamp: str
    rule_name: str
    severity: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str
    description: str
    payload_snippet: Optional[str] = None
    acknowledged: bool = False
    country: Optional[str] = "Unknown"

class CaptureFilterSchema(BaseModel):
    interface: Optional[str] = "all"
    bpf_filter: Optional[str] = ""
    is_capturing: bool = True

class StatsSchema(BaseModel):
    total_packets: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    packets_per_second: float
    bandwidth_kbps: float
    protocol_distribution: dict
    top_sources: List[dict]
    top_destinations: List[dict]
