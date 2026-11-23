from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import ALLOWED_ORIGINS, APP_TITLE, APP_VERSION
from app.routers import health, scan , analyze
from app.db.database import Base, engine
from app.db import models

Base.metadata.create_all(bind=engine)
app = FastAPI(
    title=APP_TITLE,
    description="Hedef sistemlerde otomatik keşif yapan ve bulguları AI ile "
                 "yorumlayan pentest asistanı API.",
    version=APP_VERSION,
)

# Frontend (Vite, localhost:5173) backend'e istek atabilsin diye
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Uç noktaları (endpoints) ekle
app.include_router(health.router)
app.include_router(scan.router)
app.include_router(analyze.router)
