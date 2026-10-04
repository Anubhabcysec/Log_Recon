import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class IPReport(Base):
    """Model storing complete threat intelligence report for an IP address."""
    __tablename__ = 'ip_reports'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    abuse_score = Column(Integer, default=0)
    total_reports = Column(Integer, default=0)
    country = Column(String(100), default='N/A')
    isp = Column(String(255), default='Unknown')
    open_ports = Column(Text, default='[]')        # JSON array string
    vulnerabilities = Column(Text, default='[]')   # JSON array string
    risk_level = Column(String(50), default='LOW')
    searched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "abuse_score": self.abuse_score,
            "total_reports": self.total_reports,
            "country": self.country,
            "isp": self.isp,
            "open_ports": self.open_ports,
            "vulnerabilities": self.vulnerabilities,
            "risk_level": self.risk_level,
            "searched_at": self.searched_at.isoformat() if self.searched_at else None
        }


class SearchHistory(Base):
    """Model storing lightweight search history log."""
    __tablename__ = 'search_history'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    risk_level = Column(String(50), default='LOW')
    searched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "risk_level": self.risk_level,
            "searched_at": self.searched_at.isoformat() if self.searched_at else None
        }


class ScheduledScan(Base):
    """Model storing scheduled recurring scans."""
    __tablename__ = 'scheduled_scans'

    id = Column(Integer, primary_key=True)
    target_ip = Column(String(45), nullable=False, index=True)
    interval_hours = Column(Integer, default=24, nullable=False)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    active = Column(Integer, default=1, nullable=False)  # 1 for active, 0 for inactive
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "interval_hours": self.interval_hours,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "active": bool(self.active),
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class FalsePositive(Base):
    """Model storing marked false positive CVE findings."""
    __tablename__ = 'false_positives'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(50), nullable=False, index=True)
    service_name = Column(String(100), default='', nullable=True)
    marked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "service_name": self.service_name or "",
            "marked_at": self.marked_at.isoformat() if self.marked_at else None
        }


class CorrelatedFinding(Base):
    """Model storing correlated findings that link scan results with log evidence."""
    __tablename__ = 'correlated_findings'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey('ip_reports.id'), nullable=True, index=True)
    port = Column(Integer, nullable=True)
    service = Column(String(100), nullable=True)
    cve_id = Column(String(50), nullable=True, index=True)
    log_evidence = Column(Text, default='[]')        # JSON array of matching log lines
    abuse_reports_count = Column(Integer, default=0)
    risk_verdict = Column(String(20), default='LOW') # CRITICAL / HIGH / MEDIUM / LOW
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "scan_id": self.scan_id,
            "port": self.port,
            "service": self.service,
            "cve_id": self.cve_id,
            "log_evidence": self.log_evidence,
            "abuse_reports_count": self.abuse_reports_count,
            "risk_verdict": self.risk_verdict,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class ScanLogSession(Base):
    """Model storing a combined scan + log analysis session for later retrieval."""
    __tablename__ = 'scan_log_sessions'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    scan_data = Column(Text, default='{}')           # JSON: raw scan results
    log_data = Column(Text, default='{}')            # JSON: parsed log entries
    correlation_result = Column(Text, default='{}')  # JSON: correlation output
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "scan_data": self.scan_data,
            "log_data": self.log_data,
            "correlation_result": self.correlation_result,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class PortChangeLog(Base):
    """Model tracking open port and service changes between scans for an IP."""
    __tablename__ = 'port_change_logs'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    service = Column(String(100), nullable=True)
    change_type = Column(String(30), nullable=False) # NEW_PORT / CLOSED_PORT / SERVICE_CHANGED
    previous_value = Column(String(255), nullable=True)
    current_value = Column(String(255), nullable=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "port": self.port,
            "service": self.service or "",
            "change_type": self.change_type,
            "previous_value": self.previous_value or "",
            "current_value": self.current_value or "",
            "detected_at": self.detected_at.isoformat() if self.detected_at else None
        }


class AlertLog(Base):
    """Model storing rule-based alert detections triggered during scans."""
    __tablename__ = 'alert_logs'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    rule_name = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)    # CRITICAL / HIGH / MEDIUM
    message = Column(Text, nullable=False)
    evidence = Column(Text, default='')
    triggered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence or "",
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "acknowledged": self.acknowledged
        }


class Asset(Base):
    """Model storing registered network assets for inventory tracking."""
    __tablename__ = 'assets'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    asset_type = Column(String(50), default='OTHER')  # SERVER / WORKSTATION / ROUTER / DATABASE / OTHER
    owner = Column(String(255), default='')
    description = Column(Text, default='')
    is_authorized = Column(Boolean, default=True, nullable=False)
    last_scanned = Column(DateTime, nullable=True)
    risk_level = Column(String(50), nullable=True)
    notes = Column(Text, default='')
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "asset_type": self.asset_type,
            "owner": self.owner or "",
            "description": self.description or "",
            "is_authorized": self.is_authorized,
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
            "risk_level": self.risk_level,
            "notes": self.notes or "",
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


def create_tables(db_path=None):
    """Creates database tables in database/database.db using create_engine directly."""
    if db_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_file = os.path.join(base_dir, 'database.db')
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        db_uri = f"sqlite:///{db_file}"
    elif db_path.startswith("sqlite:"):
        db_uri = db_path
    else:
        db_uri = f"sqlite:///{db_path}"
    
    engine = create_engine(db_uri, echo=False)
    Base.metadata.create_all(engine)
    return engine


if __name__ == '__main__':
    create_tables()
    print("Database tables created successfully in database/database.db!")
