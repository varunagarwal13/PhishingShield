"""Database connection, schema, and repository helpers using SQLAlchemy."""

from __future__ import annotations

import logging
from collections.abc import Generator
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

from config.settings import get_settings

settings = get_settings()
logger = logging.getLogger("phishing_shield")

# Support PostgreSQL override from environment if provided (e.g. on Render)
db_url = settings.database_url
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ThreatLog(Base):
    __tablename__ = "threat_log"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    score = Column(Float, nullable=False)
    verdict = Column(String(10), nullable=False)
    signals = Column(Text, nullable=True)
    cached = Column(Integer, default=0)
    detector_outputs = Column(Text, nullable=True)
    execution_time = Column(Float, nullable=True)
    screenshot_path = Column(String(2048), nullable=True)
    html_hash = Column(String(64), nullable=True)
    certificate_fingerprint = Column(String(128), nullable=True)
    threat_intelligence_results = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))
    user_feedback = Column(String(20), nullable=True)  # "correct", "false_positive", "proceeded"

    feedbacks = relationship("FeedbackLog", back_populates="threat_log", passive_deletes=True)


class FeedbackLog(Base):
    __tablename__ = "feedback_log"

    id = Column(Integer, primary_key=True, index=True)
    threat_log_id = Column(Integer, ForeignKey("threat_log.id", ondelete="SET NULL"), nullable=True, index=True)
    url = Column(String(2048), nullable=False)
    verdict = Column(String(10), nullable=False)
    feedback = Column(String(20), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))

    threat_log = relationship("ThreatLog", back_populates="feedbacks")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _apply_sqlite_additive_migrations()


def _apply_sqlite_additive_migrations() -> None:
    if "sqlite" not in db_url:
        return
    inspector = inspect(engine)
    if not inspector.has_table("threat_log"):
        return
    existing_columns = {column["name"] for column in inspector.get_columns("threat_log")}
    migrations = {
        "detector_outputs": "TEXT",
        "execution_time": "FLOAT",
        "screenshot_path": "VARCHAR(2048)",
        "html_hash": "VARCHAR(64)",
        "certificate_fingerprint": "VARCHAR(128)",
        "threat_intelligence_results": "TEXT",
    }
    with engine.begin() as connection:
        for column_name, column_type in migrations.items():
            if column_name not in existing_columns:
                connection.execute(text(f"ALTER TABLE threat_log ADD COLUMN {column_name} {column_type}"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_feedback(url: str, feedback_type: str, verdict: str = "UNKNOWN") -> None:
    """Inserts feedback records and links them to the latest related threat log."""
    db = SessionLocal()
    try:
        latest_log = db.query(ThreatLog).filter(ThreatLog.url == url).order_by(ThreatLog.timestamp.desc()).first()
        threat_log_id = latest_log.id if latest_log else None
        
        if latest_log:
            latest_log.user_feedback = feedback_type
            
        feedback = FeedbackLog(
            threat_log_id=threat_log_id,
            url=url[:2048],
            verdict=latest_log.verdict if latest_log else verdict,
            feedback=feedback_type,
            timestamp=datetime.now(UTC)
        )
        db.add(feedback)
        db.commit()
        logger.info(f"Feedback log written: url={url[:60]}, feedback={feedback_type}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to log feedback: {e}")
    finally:
        db.close()
