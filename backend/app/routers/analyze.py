from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.agent.analyzer import analyze_scan_results
from app.routers.scan import scan_jobs, scan_jobs_lock
from app.db.database import get_db
from app.db import crud

router = APIRouter()


@router.post("/analyze/{job_id}")
def analyze_job(job_id: str, db: Session = Depends(get_db)):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

    if job is not None:
        if job["status"] != "finished":
            raise HTTPException(status_code=400, detail="Tarama henuz bitmedi, analiz edilemez.")
        scan_result = job["result"]
    else:
        # Bellekte yok (backend yeniden baslatilmis olabilir) - DB'den oku.
        record = crud.get_scan(db, job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Bu job_id bulunamadi.")
        if record.status != "finished":
            raise HTTPException(status_code=400, detail="Tarama henuz bitmedi, analiz edilemez.")
        scan_result = record.result

    try:
        analysis = analyze_scan_results(scan_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Claude analizi sirasinda hata: {str(e)}")

    if job is not None:
        with scan_jobs_lock:
            scan_jobs[job_id]["analysis"] = analysis

    # Kalici olarak DB'ye de yaz.
    crud.save_analysis(db, job_id, analysis)

    return analysis