"""Durable append-only event tables; current state is derived from events."""

from sqlalchemy import JSON, Float, Integer, String, event, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class AuditRecord(Base):
    __tablename__ = "audit_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON)


class ChangeRecord(Base):
    __tablename__ = "change_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    change_id: Mapped[str] = mapped_column(String, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ApprovalEvent(Base):
    __tablename__ = "approval_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[str] = mapped_column(String, index=True)
    action_id: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON)


class RuntimeEvent(Base):
    __tablename__ = "runtime_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[float] = mapped_column(Float)
    payload: Mapped[dict] = mapped_column(JSON)


def database(url):
    kwargs = {"connect_args": {"check_same_thread": False}}
    if url in ("sqlite://", "sqlite:///:memory:"):
        kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def configure(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")

    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        for table in Base.metadata.tables:
            for operation in ("UPDATE", "DELETE"):
                connection.execute(
                    text(
                        f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'append-only table'); END"
                    )
                )
    return engine, sessionmaker(engine, expire_on_commit=False)
