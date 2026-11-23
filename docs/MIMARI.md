# Sistem Mimarisi Notu

> Hafta 2 çıktısı. Projenin ilerleyen haftalarında bu doküman güncellenecektir.

## 1. Genel Bakış

Sistem üç ana bileşenden oluşur:

```
┌──────────────┐      HTTP/WebSocket      ┌──────────────┐
│   Frontend   │ ───────────────────────► │   Backend    │
│ (React/Vite) │ ◄─────────────────────── │  (FastAPI)   │
└──────────────┘                          └──────┬───────┘
                                                   │
                                   ┌───────────────┼───────────────┐
                                   ▼               ▼               ▼
                            ┌───────────┐   ┌─────────────┐  ┌───────────┐
                            │ Scanners  │   │   Agent     │  │ Database  │
                            │ (Nmap vb.)│   │ (LLM karar) │  │(Postgres) │
                            └─────┬─────┘   └──────┬──────┘  └───────────┘
                                  │                 │
                                  ▼                 ▼
                         ┌──────────────────────────────┐
                         │  İzole Test Ortamı (Docker)   │
                         │  Juice Shop · DVWA             │
                         └────────────────────────────────┘
```

## 2. Bileşenlerin Sorumlulukları

| Bileşen | Sorumluluk | Durum |
|---|---|---|
| **Frontend** | Hedef girişi, tarama durumunun gerçek zamanlı gösterimi | Hafta 1'de temel hâli kuruldu |
| **Backend (core)** | İstekleri karşılama, CORS, yönlendirme | Hafta 1'de kuruldu |
| **Scanners** | Nmap/Sublist3r/WhatWeb/Nuclei'yi çalıştırıp JSON çıktı üretme | Hafta 3-5'te doldurulacak |
| **Agent** | Scanner çıktısını LLM'e verip yorumlatma, karar döngüsü | Hafta 6-8'de doldurulacak |
| **Database** | Tarama geçmişi, bulgular | Hafta 9'da doldurulacak |

## 3. Veri Akışı (Bir Taramanın Hayat Döngüsü)

1. Kullanıcı frontend'den bir hedef adresi girer (örn. `http://localhost:3000`).
2. Frontend, backend'in `/scan` uç noktasına bu hedefi POST eder.
3. Backend isteği doğrular (`ScanRequest` modeli ile) ve `scanners/` modülüne iletir.
4. Scanners modülü, sırasıyla keşif araçlarını çalıştırır ve çıktıları standart bir
   JSON formatına dönüştürür.
5. Bu JSON, `agent/` modülüne gönderilir; LLM bulguları yorumlar ve önceliklendirir.
6. Sonuç, WebSocket üzerinden frontend'e gerçek zamanlı olarak geri bildirilir.
7. Tarama sonucu veritabanına kaydedilir (geçmiş tarama kayıtları için).

## 4. Neden Bu Katmanlara Ayırdık?

- **Ayrı sorumluluklar:** `scanners/` ve `agent/` modülleri birbirinden bağımsızdır.
  Agent mantığını değiştirmek scanner kodunu bozmaz.
- **Test edilebilirlik:** Her modül tek başına test edilebilir (örn. scanners modülünü
  LLM olmadan da çalıştırıp çıktısını kontrol edebiliriz).
- **Kademeli geliştirme:** Haftalık plana net biçimde oturuyor — her hafta bir modülü
  dolduruyoruz, önceki haftaların çalışır hâli bozulmuyor.

## 5. Bir Sonraki Adım (Hafta 3)

`backend/app/scanners/` klasörüne ilk gerçek entegrasyonu (Nmap) ekleyeceğiz.
