"""Environment-backed controller configuration."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class ControllerSettings:
    openflow_port: int
    rest_host: str
    rest_port: int
    stats_interval_seconds: float = 1.0
    path_distribution_threshold_pps: float = 800.0
    path_distribution_recovery_pps: float = 600.0
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
    stats_interval = float(environ.get("CONTROLLER_STATS_INTERVAL_SECONDS", "1"))
    if stats_interval <= 0:
        raise ValueError("CONTROLLER_STATS_INTERVAL_SECONDS must be positive")
    distribution_threshold = float(
        environ.get("PATH_DISTRIBUTION_THRESHOLD_PPS", "800")
    )
    distribution_recovery = float(
        environ.get("PATH_DISTRIBUTION_RECOVERY_PPS", "600")
    )
    if distribution_threshold <= 0:
        raise ValueError("PATH_DISTRIBUTION_THRESHOLD_PPS must be positive")
    if (
        distribution_recovery < 0
        or distribution_recovery >= distribution_threshold
    ):
        raise ValueError(
            "PATH_DISTRIBUTION_RECOVERY_PPS must be non-negative and below "
            "PATH_DISTRIBUTION_THRESHOLD_PPS"
        )
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
        path_distribution_threshold_pps=distribution_threshold,
        path_distribution_recovery_pps=distribution_recovery,
        api_key=environ.get("CONTROLLER_API_KEY", ""),
        allow_insecure_dev_auth=_read_bool(
            environ,
            "ALLOW_INSECURE_DEV_AUTH",
        ),
    )
