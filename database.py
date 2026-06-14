"""SQLAlchemy engine + session factory.

Auto-rewrites the legacy ``postgres://`` URL scheme that Railway/Heroku
hand out to ``postgresql://`` so SQLAlchemy 2.x accepts it without a fuss.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings


_url = settings.DATABASE_URL
if _url.startswith("postgres://"):
    _url = "postgresql://" + _url[len("postgres://"):]

engine = create_engine(
    _url,
    connect_args={"check_same_thread": False} if _url.startswith("sqlite") else {},
    pool_pre_ping=True,   # heals stale Postgres connections after long idle periods
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
