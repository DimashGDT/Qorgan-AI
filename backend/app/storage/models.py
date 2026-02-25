from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trace_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    url_hash: Mapped[str] = mapped_column(String(64))   # sha256 of url, NOT the url
    domain: Mapped[str] = mapped_column(String(253))
    score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(20))
    model_version: Mapped[str] = mapped_column(String(32))
    features_json: Mapped[str] = mapped_column(Text)   # truncated JSON blob


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user_label: Mapped[str] = mapped_column(String(10))
    comment: Mapped[str] = mapped_column(Text, default="")
