import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
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
