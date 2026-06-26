from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone
import os

# Local = SQLite, Production = PostgreSQL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_log.db")

# Render.com provides postgres:// but SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class ThreatLog(Base):
    __tablename__ = "threat_log"

    id          = Column(Integer, primary_key=True, index=True)
    url         = Column(String(2048), nullable=False)
    score       = Column(Float, nullable=False)
    verdict     = Column(String(10), nullable=False)
    signals     = Column(Text, nullable=True)
    rf_score    = Column(Float, nullable=True)
    xgb_score   = Column(Float, nullable=True)
    vt_malicious= Column(Integer, nullable=True)
    vt_total    = Column(Integer, nullable=True)
    cached      = Column(Integer, default=0)
    timestamp   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    user_feedback = Column(String(20), nullable=True)  # "correct", "false_positive", "false_negative"

    # Fix #10: one-to-many relationship — each ThreatLog can have multiple FeedbackLog entries
    feedbacks   = relationship("FeedbackLog", back_populates="threat_log", passive_deletes=True)


class FeedbackLog(Base):
    __tablename__ = "feedback_log"

    id            = Column(Integer, primary_key=True, index=True)
    # Fix #10: FK links FeedbackLog to the specific ThreatLog entry it refers to.
    # nullable=True keeps existing rows valid; set nullable=False once data is migrated.
    threat_log_id = Column(Integer, ForeignKey("threat_log.id", ondelete="SET NULL"), nullable=True, index=True)
    url           = Column(String(2048), nullable=False)
    verdict       = Column(String(10), nullable=False)
    feedback      = Column(String(20), nullable=False)
    timestamp     = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    threat_log    = relationship("ThreatLog", back_populates="feedbacks")


def init_db():
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized: {DATABASE_URL}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
