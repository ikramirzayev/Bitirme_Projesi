"""
Uygulama genelinde kullanılan ayarlar burada toplanır.
İleride .env dosyasından okunacak değerler (API anahtarı, hedef URL'ler vb.)
de bu dosyaya eklenecektir.
"""

# Frontend'in çalıştığı adresler - CORS için izin verilenler
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

APP_TITLE = "AI Destekli Otonom Pentest Ajanı"
APP_VERSION = "0.2.0"
