from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.models import ScanRecord


def create_scan(db: Session, job_id: str, target: str):
    record = ScanRecord(id=job_id, target=target, status="running")
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def finish_scan(db: Session, job_id: str, result: dict):
    record = db.query(ScanRecord).filter(ScanRecord.id == job_id).first()
    if record is None:
        return None
    record.status = "finished"
    record.result = result
    record.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    return record


def save_analysis(db: Session, job_id: str, analysis: dict):
    record = db.query(ScanRecord).filter(ScanRecord.id == job_id).first()
    if record is None:
        return None
    record.analysis = analysis
    db.commit()
    db.refresh(record)
    return record


def get_scan(db: Session, job_id: str):
    return db.query(ScanRecord).filter(ScanRecord.id == job_id).first()


def list_scans(db: Session, limit: int = 50):
    return (
        db.query(ScanRecord)
        .order_by(desc(ScanRecord.created_at))
        .limit(limit)
        .all()
    )