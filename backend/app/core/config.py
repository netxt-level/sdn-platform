import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    @property
    def postgres_dsn(self) -> str:
        host = get_env("POSTGRES_HOST", "localhost")
        port = get_env("POSTGRES_PORT", "5432")
        user = get_env("POSTGRES_USER")
        password = get_env("POSTGRES_PASSWORD")
        database = get_env("POSTGRES_DB")
        return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{database}"

    @property
    def influxdb_url(self) -> str:
        host = get_env("INFLUXDB_HOST", "localhost")
        port = get_env("INFLUXDB_PORT", "8086")
        return f"http://{host}:{port}"

    @property
    def influxdb_token(self) -> str:
        return get_env("INFLUXDB_TOKEN")

    @property
    def influxdb_org(self) -> str:
        return get_env("INFLUXDB_ORG")

    @property
    def influxdb_bucket(self) -> str:
        return get_env("INFLUXDB_BUCKET")

    @property
    def elasticsearch_url(self) -> str:
        host = get_env("ELASTICSEARCH_HOST", "localhost")
        port = get_env("ELASTICSEARCH_HTTP_PORT", "9200")
        return f"http://{host}:{port}"

    @property
    def controller_base_url(self) -> str:
        return get_env("CONTROLLER_BASE_URL", "http://host.docker.internal:8080")

    @property
    def controller_timeout_seconds(self) -> float:
        value = float(get_env("CONTROLLER_TIMEOUT_SECONDS", "8"))
        if value <= 0:
            raise RuntimeError("CONTROLLER_TIMEOUT_SECONDS must be positive")
        return value

    @property
    def controller_max_attempts(self) -> int:
        value = int(get_env("CONTROLLER_MAX_ATTEMPTS", "2"))
        if value < 1:
            raise RuntimeError("CONTROLLER_MAX_ATTEMPTS must be at least 1")
        return value


settings = Settings()
