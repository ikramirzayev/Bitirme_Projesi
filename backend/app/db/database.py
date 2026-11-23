from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./pentest.db"

# SQLite icin check_same_thread=False sart: biz taramayi ayri bir thread'de
# calistiriyoruz (scan.py'deki threading.Thread), o thread de ayni DB
# dosyasina baglanmak zorunda. Bu bayrak olmadan SQLite hata verir.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency: her HTTP istegi icin ayri bir DB session acar,
    istek bitince otomatik kapatir."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()