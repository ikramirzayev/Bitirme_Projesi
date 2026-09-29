"""
AI Destekli Otonom Pentest Ajanı - Backend API
------------------------------------------------
Bu dosya, projenin ilk hafta hedefine uygun minimal bir iskelettir:
- FastAPI uygulamasının ayağa kalktığını doğrulayan bir health-check endpoint'i
- İleride keşif araçlarını (Nmap, Sublist3r vb.) tetikleyecek bir taslak endpoint

Her yeni özellik eklerken bu dosyayı büyütmek yerine ayrı modüllere
(örn. app/scanners/, app/agent/, app/routers/) bölmen önerilir.
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="AI Destekli Otonom Pentest Ajanı",
    description="Hedef sistemlerde otomatik keşif yapan ve bulguları AI ile "
                 "yorumlayan pentest asistanı API'si.",
    version="0.1.0",
)


class ScanRequest(BaseModel):
    target: str  # Örn: "http://localhost:3000" (yalnızca izole test ortamı!)


@app.get("/health")
def health_check():
    """Servisin ayakta olup olmadığını kontrol etmek için basit bir uç nokta."""
    return {"status": "ok", "message": "Backend calisiyor"}


@app.post("/scan")
def start_scan(request: ScanRequest):
    """
    Taslak endpoint: ileride burada
    1) Nmap/Sublist3r/WhatWeb/Nuclei sırayla çalıştırılacak,
    2) Sonuçlar JSON formatında birleştirilecek,
    3) LLM'e gönderilip yorumlanacak.

    Şimdilik sadece isteği doğrulayıp sabit bir yanıt döndürür.
    """
    return {
        "target": request.target,
        "status": "queued",
        "note": "Tarama motoru henuz baglanmadi - bu bir yer tutucu yanittir.",
    }
