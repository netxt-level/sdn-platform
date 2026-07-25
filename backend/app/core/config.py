import os
from dataclasses import dataclass
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()


def get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


def get_bool_env(name: str, default: bool = False) -> bool:
    value = get_env(name, "true" if default else "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Settings:
    @property
    def postgres_dsn(self) -> str:
        host = get_env("POSTGRES_HOST", "localhost")
        port = get_env("POSTGRES_PORT", "5432")
        user = get_env("POSTGRES_USER")
        password = get_env("POSTGRES_PASSWORD")
        database = get_env("POSTGRES_DB")
        return (
            "postgresql+psycopg://"
            f"{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/"
            f"{quote_plus(database)}"
        )

    @property
    def admin_api_key(self) -> str:
        return get_env("ADMIN_API_KEY", "")

    @property
    def analyzer_api_key(self) -> str:
        return get_env("ANALYZER_API_KEY", "")

    @property
    def controller_api_key(self) -> str:
        return get_env("CONTROLLER_API_KEY", "")

    @property
    def websocket_token_secret(self) -> str:
        return get_env("WEBSOCKET_TOKEN_SECRET", "")

    @property
    def websocket_allowed_origins(self) -> tuple[str, ...]:
        value = get_env(
            "WEBSOCKET_ALLOWED_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        )
        return tuple(origin.strip() for origin in value.split(",") if origin.strip())

    @property
    def websocket_token_ttl_seconds(self) -> int:
        value = int(get_env("WEBSOCKET_TOKEN_TTL_SECONDS", "60"))
        if not 10 <= value <= 300:
            raise RuntimeError(
                "WEBSOCKET_TOKEN_TTL_SECONDS must be between 10 and 300"
            )
        return value

    @property
    def websocket_send_timeout_seconds(self) -> float:
        value = float(get_env("WEBSOCKET_SEND_TIMEOUT_SECONDS", "2"))
        if value <= 0:
            raise RuntimeError("WEBSOCKET_SEND_TIMEOUT_SECONDS must be positive")
        return value

    @property
    def allow_insecure_dev_auth(self) -> bool:
        return get_bool_env("ALLOW_INSECURE_DEV_AUTH", False)

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

    @property
    def flow_reconcile_interval_seconds(self) -> float:
        value = float(get_env("FLOW_RECONCILE_INTERVAL_SECONDS", "30"))
        if value <= 0:
            raise RuntimeError(
                "FLOW_RECONCILE_INTERVAL_SECONDS must be positive"
            )
        return value

    @property
    def switch_port_capacity_bps(self) -> int:
        value = int(get_env("SWITCH_PORT_CAPACITY_BPS", "10000000"))
        if value <= 0:
            raise RuntimeError("SWITCH_PORT_CAPACITY_BPS must be positive")
        return value


settings = Settings()
