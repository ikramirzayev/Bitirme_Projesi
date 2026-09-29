# Haftalık Çalışma Planı (Tek Dönem — 14 Hafta)

> Not: Bu dosya, Word/PDF dokümanındaki resmi çalışma planının kısa bir referansıdır.
> Danışman onayı sonrası güncel tutulmalıdır.

| Hafta | Çalışma Konusu | Beklenen Çıktı |
|---|---|---|
| 1 | Repo kurulumu, izole test ortamının (Docker) ayağa kaldırılması, hızlı literatür taraması | Çalışır repo + test ortamı |
| 2 | Sistem mimarisinin netleştirilmesi, backend iskeletinin genişletilmesi | Mimari not + genişletilmiş backend |
| 3 | Nmap / Sublist3r / WhatWeb entegrasyonu | Çalışan keşif modülü |
| 4 | Araç çıktılarını birleştiren orkestrasyon katmanı | Standart JSON çıktı |
| 5 | Nuclei entegrasyonu, sonuçların veri modeline oturtulması | Genişletilmiş tarama motoru |
| 6 | LLM API entegrasyonu (basit prompt ile yorumlama) | Çalışan LLM prototipi |
| 7 | Agent mimarisine geçiş (çok adımlı karar döngüsü) | Çalışan AI-agent çekirdeği |
| 8 | Backend API'lerinin tamamlanması, veritabanı şeması | Tamamlanmış backend |
| 9 | Web arayüzü: gerçek zamanlı tarama takibi (WebSocket) | Çalışan dashboard |
| 10 | Dashboard: risk skorlama görselleri, filtreleme | Tamamlanmış dashboard |
| 11 | Raporlama modülü (CVSS skoru, PDF/rapor çıktısı) | Raporlama modülü |
| 12 | Uçtan uca test, hata düzeltmeleri | Kararlı sürüm |
| 13 | Performans ölçümü, dokümantasyon | Metrikler + kullanıcı kılavuzu |
| 14 | Sunum hazırlığı, final rapor | Bitirme raporu + demo |

## Etik Çerçeve

- Sistem yalnızca izole/sanal test ortamlarında (Docker: Juice Shop, DVWA) çalıştırılır.
- Gerçek/izinsiz sistemlere karşı hiçbir tarama veya saldırı işlemi yapılmaz.
- Tüm işlemler loglanır; şeffaf bir denetim izi tutulur.
