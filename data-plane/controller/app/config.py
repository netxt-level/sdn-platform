"""Environment-backed controller configuration."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class ControllerSettings:
    openflow_port: int
    rest_host: str
    rest_port: int


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
    )
