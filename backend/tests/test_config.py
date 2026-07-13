import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy.engine import make_url

from app.core.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]


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


def test_alembic_offline_migration_handles_reserved_password_characters():
    env = os.environ.copy()
    env.update({
        "POSTGRES_HOST": "localhost",
        "POSTGRES_PORT": "5432",
        "POSTGRES_USER": "sdn_user",
        "POSTGRES_PASSWORD": "p@ss:word/with#chars",
        "POSTGRES_DB": "sdn_db",
    })

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "CREATE TABLE" in result.stdout
