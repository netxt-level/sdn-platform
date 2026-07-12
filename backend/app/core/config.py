import os
from dataclasses import dataclass

from dotenv import load_dotenv
from sqlalchemy.engine import URL

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
        return URL.create(
            drivername="postgresql+psycopg",
            username=user,
            password=password,
            host=host,
            port=int(port),
            database=database,
        ).render_as_string(hide_password=False)

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
    def analyzer_api_key(self) -> str:
        return os.getenv("ANALYZER_API_KEY", "").strip()

    @property
    def admin_api_key(self) -> str:
        return os.getenv("ADMIN_API_KEY", "").strip()

    @property
    def allow_insecure_dev_auth(self) -> bool:
        return os.getenv("ALLOW_INSECURE_DEV_AUTH", "").strip().lower() in {
            "1",
            "true",
            "yes",
        }


settings = Settings()
