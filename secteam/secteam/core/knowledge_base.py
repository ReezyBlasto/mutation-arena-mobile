"""
Persistent knowledge base backed by SQLite.  Stores:
  - Research results (CVE lookups, MITRE queries, web searches, man pages)
  - System inventory snapshots (baseline + history)
  - Incident records
  - Agent decisions and their outcomes (training data collection)
  - Security tool recommendations and their status

Research results are cached by query hash to avoid re-querying the same thing
in the same session and across sessions.
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text,
    create_engine, text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from secteam.models import (
    ActionResult, IncidentReport, ResearchResult, SecurityEvent, SystemInventory,
)

log = logging.getLogger(__name__)

DB_PATH = Path(os.environ.get("SECTEAM_DATA", "/var/lib/secteam")) / "knowledge.db"


class Base(DeclarativeBase):
    pass


class ResearchCache(Base):
    __tablename__ = "research_cache"
    id         = Column(Integer, primary_key=True)
    query_hash = Column(String(64), unique=True, index=True)
    query      = Column(Text)
    source     = Column(String(64))
    content    = Column(Text)
    confidence = Column(Float)
    urls       = Column(Text)   # JSON list
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"
    id         = Column(Integer, primary_key=True)
    taken_at   = Column(DateTime, default=datetime.utcnow, index=True)
    is_baseline= Column(Boolean, default=False)
    data       = Column(Text)   # JSON of SystemInventory
    posture_score = Column(Float, nullable=True)


class EventRecord(Base):
    __tablename__ = "events"
    id           = Column(String(36), primary_key=True)
    timestamp    = Column(DateTime, index=True)
    source       = Column(String(64), index=True)
    severity     = Column(String(16), index=True)
    event_type   = Column(String(64), index=True)
    raw          = Column(Text)
    enriched     = Column(Text)  # JSON
    confidence   = Column(Float)
    resolved     = Column(Boolean, default=False)
    resolution   = Column(Text, nullable=True)


class ActionRecord(Base):
    __tablename__ = "action_records"
    id           = Column(Integer, primary_key=True)
    timestamp    = Column(DateTime, default=datetime.utcnow)
    action_name  = Column(String(128))
    agent        = Column(String(64))
    confidence   = Column(Float)
    reasoning    = Column(Text)
    result       = Column(Text)   # JSON
    research     = Column(Text, nullable=True)
    error        = Column(Text, nullable=True)


class TrainingDataRecord(Base):
    """Accumulates examples for future fine-tuning."""
    __tablename__ = "training_data"
    id         = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    role       = Column(String(64))
    instruction= Column(Text)
    input_ctx  = Column(Text)
    output     = Column(Text)
    domain     = Column(String(64))   # cve, log_analysis, hardening, etc.
    quality    = Column(Float, default=1.0)   # 0-1, filtered before export


class ToolRecommendation(Base):
    __tablename__ = "tool_recommendations"
    name       = Column(String(64), primary_key=True)
    status     = Column(String(32))
    approved   = Column(Boolean, default=False)
    installed_at = Column(DateTime, nullable=True)
    notes      = Column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────────────────────

class KnowledgeBase:
    def __init__(self, db_path: Path = DB_PATH):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(bind=self.engine)
        log.info("KnowledgeBase initialized at %s", db_path)

    def _session(self) -> Session:
        return self._Session()

    # ── Research cache ────────────────────────────────────────────────────

    @staticmethod
    def _hash(query: str, source: str) -> str:
        return hashlib.sha256(f"{source}:{query}".encode()).hexdigest()

    def get_research(self, query: str, source: str = "any",
                     max_age_hours: int = 24) -> Optional[ResearchResult]:
        h = self._hash(query, source)
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        with self._session() as s:
            row = s.query(ResearchCache).filter(
                ResearchCache.query_hash == h,
                ResearchCache.created_at >= cutoff,
            ).first()
            if row:
                return ResearchResult(
                    query=row.query,
                    source=row.source,
                    content=row.content,
                    confidence=row.confidence,
                    cached=True,
                    urls=json.loads(row.urls or "[]"),
                )
        return None

    def save_research(self, result: ResearchResult, ttl_hours: int = 24) -> None:
        h = self._hash(result.query, result.source)
        with self._session() as s:
            existing = s.query(ResearchCache).filter_by(query_hash=h).first()
            if existing:
                existing.content    = result.content
                existing.confidence = result.confidence
                existing.urls       = json.dumps(result.urls)
                existing.created_at = datetime.utcnow()
                existing.expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
            else:
                s.add(ResearchCache(
                    query_hash=h,
                    query=result.query,
                    source=result.source,
                    content=result.content,
                    confidence=result.confidence,
                    urls=json.dumps(result.urls),
                    expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
                ))
            s.commit()

    # ── Inventory ─────────────────────────────────────────────────────────

    def save_inventory(self, inv: SystemInventory, baseline: bool = False) -> None:
        with self._session() as s:
            s.add(InventorySnapshot(
                taken_at=inv.timestamp,
                is_baseline=baseline,
                data=inv.model_dump_json(),
                posture_score=inv.posture_score,
            ))
            s.commit()
        log.info("Saved inventory snapshot (baseline=%s)", baseline)

    def get_baseline(self) -> Optional[SystemInventory]:
        with self._session() as s:
            row = s.query(InventorySnapshot).filter_by(
                is_baseline=True
            ).order_by(InventorySnapshot.taken_at.desc()).first()
            if row:
                return SystemInventory.model_validate_json(row.data)
        return None

    def get_latest_inventory(self) -> Optional[SystemInventory]:
        with self._session() as s:
            row = s.query(InventorySnapshot).order_by(
                InventorySnapshot.taken_at.desc()
            ).first()
            if row:
                return SystemInventory.model_validate_json(row.data)
        return None

    # ── Events ────────────────────────────────────────────────────────────

    def save_event(self, event: SecurityEvent) -> None:
        with self._session() as s:
            s.merge(EventRecord(
                id=event.id,
                timestamp=event.timestamp,
                source=event.source,
                severity=event.severity.value,
                event_type=event.event_type,
                raw=event.raw,
                enriched=json.dumps(event.enriched),
                confidence=event.confidence,
                resolved=event.resolved,
                resolution=event.resolution,
            ))
            s.commit()

    def open_events(self, severity: Optional[str] = None) -> list[SecurityEvent]:
        with self._session() as s:
            q = s.query(EventRecord).filter_by(resolved=False)
            if severity:
                q = q.filter_by(severity=severity)
            rows = q.order_by(EventRecord.timestamp.desc()).all()
            events = []
            for r in rows:
                events.append(SecurityEvent(
                    id=r.id,
                    timestamp=r.timestamp,
                    source=r.source,
                    severity=r.severity,  # type: ignore
                    event_type=r.event_type,
                    raw=r.raw,
                    enriched=json.loads(r.enriched or "{}"),
                    confidence=r.confidence,
                    resolved=r.resolved,
                    resolution=r.resolution,
                ))
            return events

    def resolve_event(self, event_id: str, resolution: str) -> None:
        with self._session() as s:
            s.query(EventRecord).filter_by(id=event_id).update({
                "resolved": True,
                "resolution": resolution,
            })
            s.commit()

    # ── Actions ───────────────────────────────────────────────────────────

    def save_action(self, result: ActionResult) -> None:
        with self._session() as s:
            s.add(ActionRecord(
                timestamp=result.timestamp,
                action_name=result.action_name,
                agent=result.agent,
                confidence=result.confidence,
                reasoning=result.reasoning,
                result=json.dumps(result.result, default=str),
                research=result.research_results,
                error=result.error,
            ))
            s.commit()

    # ── Training data ─────────────────────────────────────────────────────

    def add_training_example(self, role: str, instruction: str,
                              input_ctx: str, output: str,
                              domain: str, quality: float = 1.0) -> None:
        with self._session() as s:
            s.add(TrainingDataRecord(
                role=role,
                instruction=instruction,
                input_ctx=input_ctx,
                output=output,
                domain=domain,
                quality=quality,
            ))
            s.commit()

    def export_training_data(self, min_quality: float = 0.7,
                              domain: Optional[str] = None) -> list[dict]:
        with self._session() as s:
            q = s.query(TrainingDataRecord).filter(
                TrainingDataRecord.quality >= min_quality
            )
            if domain:
                q = q.filter_by(domain=domain)
            rows = q.all()
            return [
                {
                    "messages": [
                        {"role": "system", "content": r.instruction},
                        {"role": "user",   "content": r.input_ctx},
                        {"role": "assistant", "content": r.output},
                    ],
                    "domain": r.domain,
                    "quality": r.quality,
                }
                for r in rows
            ]

    def training_data_count(self) -> dict[str, int]:
        with self._session() as s:
            rows = s.execute(
                text("SELECT domain, COUNT(*) FROM training_data GROUP BY domain")
            ).fetchall()
            return {row[0]: row[1] for row in rows}

    # ── Tool recommendations ──────────────────────────────────────────────

    def save_tool_recommendation(self, name: str, status: str) -> None:
        with self._session() as s:
            existing = s.query(ToolRecommendation).filter_by(name=name).first()
            if not existing:
                s.add(ToolRecommendation(name=name, status=status))
                s.commit()

    def approve_tool(self, name: str) -> None:
        with self._session() as s:
            s.query(ToolRecommendation).filter_by(name=name).update({"approved": True})
            s.commit()

    def get_approved_tools(self) -> list[str]:
        with self._session() as s:
            return [r.name for r in s.query(ToolRecommendation).filter_by(approved=True).all()]
