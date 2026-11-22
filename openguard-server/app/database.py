from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)


def apply_sqlite_pragmas(dbapi_connection, _connection_record=None) -> None:
    """Enable WAL mode, foreign key checks, and busy timeout on SQLite connections."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.close()


def register_sqlite_pragmas(target_engine) -> None:
    """Attach SQLite pragma setup to every new DBAPI connection."""
    if target_engine.dialect.name == "sqlite":
        event.listen(target_engine, "connect", apply_sqlite_pragmas)


register_sqlite_pragmas(engine)


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
