from sqlalchemy.engine import make_url

from app.core.config import Settings


def test_postgres_dsn_handles_reserved_password_characters(monkeypatch):
    monkeypatch.setenv("POSTGRES_HOST", "localhost")
    monkeypatch.setenv("POSTGRES_PORT", "5432")
    monkeypatch.setenv("POSTGRES_USER", "sdn_user")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss:word/with#chars")
    monkeypatch.setenv("POSTGRES_DB", "sdn_db")

    url = make_url(Settings().postgres_dsn)

    assert url.drivername == "postgresql+psycopg"
    assert url.username == "sdn_user"
    assert url.password == "p@ss:word/with#chars"
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "sdn_db"
