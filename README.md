# AI Destekli Otonom Pentest Ajanı

Bir pentest uzmanının hedef sistemleri değerlendirirken izlediği düşünme ve karar verme
sürecini taklit eden, yapay zeka destekli otonom bir ajan. Sistem izole ve yetkili bir test
ortamında klasik keşif (recon) araçlarını otomatik çalıştırır, bulguları bir LLM ile
yorumlayarak önceliklendirilmiş risk alanlarını ve gerekçeli öneriler sunar.

> ⚠️ **Sadece izole/yetkili test ortamlarında kullanılmak üzere tasarlanmıştır.**
> Gerçek, izinsiz sistemlere karşı kullanılamaz.

## Proje Yapısı

```
.
├── backend/          # FastAPI tabanlı API, keşif araçları entegrasyonu, LLM/agent mantığı
├── frontend/         # React (Vite) tabanlı web dashboard
├── docs/             # Proje önerisi, çalışma planı, mimari notlar
├── docker-compose.yml  # İzole test ortamı (OWASP Juice Shop, DVWA)
└── README.md
```

## Hızlı Başlangıç

### 1. İzole test ortamını ayağa kaldır
```bash
docker compose up -d
```
Bu komut, hedef olarak kullanılacak zafiyetli uygulamaları başlatır:
- OWASP Juice Shop → http://localhost:3000
- DVWA → http://localhost:8081

### 2. Backend'i çalıştır
```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # ve içine kendi API anahtarını gir
uvicorn app.main:app --reload
```
API varsayılan olarak http://localhost:8000 üzerinde çalışır. `/docs` adresinden
otomatik oluşturulan Swagger arayüzüne erişebilirsin.

### 3. Frontend'i çalıştır
```bash
cd frontend
npm install
npm run dev
```

## Kullanılan Teknolojiler

| Katman | Teknoloji |
|---|---|
| Backend | Python + FastAPI |
| Keşif Araçları | Nmap, Sublist3r, WhatWeb, Nuclei |
| Yapay Zeka | LLM API (tool use / function calling) |
| Web Arayüzü | React (Vite) |
| Gerçek Zamanlı İletişim | WebSocket |
| Test Ortamı | Docker (OWASP Juice Shop, DVWA) |

## Yol Haritası

Detaylı haftalık çalışma planı için [`docs/CALISMA_PLANI.md`](docs/CALISMA_PLANI.md)
dosyasına bakınız.

## Etik Kullanım

Bu proje yalnızca akademik amaçlarla, kendi kurulan izole test ortamlarında
kullanılmak üzere geliştirilmektedir. Üçüncü taraf sistemlere karşı izinsiz
kullanımı geliştiricinin sorumluluğundadır ve önerilmez.
