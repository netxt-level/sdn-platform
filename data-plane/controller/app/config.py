"""Environment-backed controller configuration."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class ControllerSettings:
    openflow_port: int
    rest_host: str
    rest_port: int
    stats_interval_seconds: float = 5.0
    api_key: str = ""
    allow_insecure_dev_auth: bool = False


def _read_bool(environ, name, default=False):
    raw_value = str(environ.get(name, "true" if default else "false")).lower()
    if raw_value in {"1", "true", "yes", "on"}:
        return True
    if raw_value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _read_port(environ, name, default):
    raw_value = environ.get(name, str(default))
    try:
        port = int(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error

    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port


def load_settings(environ=None):
    environ = os.environ if environ is None else environ
    stats_interval = float(environ.get("CONTROLLER_STATS_INTERVAL_SECONDS", "5"))
    if stats_interval <= 0:
        raise ValueError("CONTROLLER_STATS_INTERVAL_SECONDS must be positive")
    return ControllerSettings(
        openflow_port=_read_port(
            environ,
            "CONTROLLER_OPENFLOW_PORT",
            6653,
        ),
        rest_host=environ.get("CONTROLLER_REST_HOST", "0.0.0.0"),
        rest_port=_read_port(
            environ,
            "CONTROLLER_REST_PORT",
            8080,
        ),
        stats_interval_seconds=stats_interval,
        api_key=environ.get("CONTROLLER_API_KEY", ""),
        allow_insecure_dev_auth=_read_bool(
            environ,
            "ALLOW_INSECURE_DEV_AUTH",
        ),
    )
