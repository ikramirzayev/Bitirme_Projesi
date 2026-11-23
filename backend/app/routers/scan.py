import uuid
import threading
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.scanners.orchestrator import run_full_recon
from app.db.database import SessionLocal, get_db
from app.db import crud

router = APIRouter()


class ScanRequest(BaseModel):
    target: str


# Canli ilerleme (progress/percent) hala bellekte - saniyede bir kac kere
# okunuyor, DB'ye bu kadar sik yazmak gereksiz yuk olur. Ama tarama BITINCE
# sonuc artik DB'ye de yaziliyor (bkz. _run_scan_job), boylece backend
# yeniden baslasa bile gecmis taramalar kaybolmuyor.
scan_jobs = {}
scan_jobs_lock = threading.Lock()

MODULES = ["nmap", "nuclei_juice", "nuclei_dvwa", "subdomains", "tech_juice", "tech_dvwa"]


def _run_scan_job(job_id, target):
    """Bu fonksiyon AYRI BIR THREAD icinde calisir, HTTP istegini bloklamaz."""

    def on_module_done(module_name):
        with scan_jobs_lock:
            scan_jobs[job_id]["progress"][module_name] = "done"

    result = run_full_recon(target, on_module_done=on_module_done)

    with scan_jobs_lock:
        scan_jobs[job_id]["status"] = "finished"
        scan_jobs[job_id]["result"] = result

    # DB'ye kalici yaz. Thread icindeyiz, FastAPI'nin Depends(get_db)
    # mekanizmasi burada kullanilamaz (o sadece HTTP istekleri icin calisir),
    # o yuzden kendi session'imizi elle aciyoruz.
    db = SessionLocal()
    try:
        crud.finish_scan(db, job_id, result)
    finally:
        db.close()


@router.post("/scan")
def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
    job_id = str(uuid.uuid4())

    with scan_jobs_lock:
        scan_jobs[job_id] = {
            "status": "running",
            "progress": {m: "pending" for m in MODULES},
            "result": None,
        }

    # Tarama baslar baslamaz DB'de "running" durumunda bir kayit aciyoruz.
    crud.create_scan(db, job_id, request.target)

    thread = threading.Thread(target=_run_scan_job, args=(job_id, request.target), daemon=True)
    thread.start()

    return {"job_id": job_id}


@router.get("/scan/status/{job_id}")
def get_scan_status(job_id: str, db: Session = Depends(get_db)):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

    if job is None:
        # Bellekte yok (orn. backend yeniden baslatildi) - DB'ye bak.
        record = crud.get_scan(db, job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Bu job_id bulunamadi.")
        return {
            "status": record.status,
            "progress": {m: "done" for m in MODULES} if record.status == "finished" else {},
            "percent": 100 if record.status == "finished" else 0,
            "result": record.result,
        }

    done_count = sum(1 for v in job["progress"].values() if v == "done")
    total_count = len(job["progress"])
    percent = int((done_count / total_count) * 100)

    return {
        "status": job["status"],
        "progress": job["progress"],
        "percent": percent,
        "result": job["result"],
    }


@router.get("/scans")
def get_scan_history(db: Session = Depends(get_db)):
    """Gecmis taramalarin listesi (Hafta 9 - DB entegrasyonu)."""
    records = crud.list_scans(db)
    return [
        {
            "job_id": r.id,
            "target": r.target,
            "status": r.status,
            "created_at": r.created_at,
            "finished_at": r.finished_at,
        }
        for r in records
    ]


@router.get("/scans/{job_id}")
def get_scan_detail(job_id: str, db: Session = Depends(get_db)):
    """Belirli bir gecmis taramanin TAM detayi (sonuc + varsa AI analizi)."""
    record = crud.get_scan(db, job_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Bu job_id bulunamadi.")

    return {
        "job_id": record.id,
        "target": record.target,
        "status": record.status,
        "created_at": record.created_at,
        "finished_at": record.finished_at,
        "result": record.result,
        "analysis": record.analysis,
    }