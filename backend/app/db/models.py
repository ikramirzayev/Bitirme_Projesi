from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.sql import func
from app.db.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)  # job_id (uuid)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False, default="running")  # running / finished

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)

    result = Column(JSON, nullable=True)     # orchestrator.py'nin tam ciktisi
    analysis = Column(JSON, nullable=True)   # Claude'un AI analizi (varsa)