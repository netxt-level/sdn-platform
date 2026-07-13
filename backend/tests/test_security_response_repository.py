import os


os.environ.setdefault("POSTGRES_USER", "sdn")
os.environ.setdefault("POSTGRES_PASSWORD", "sdn")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "sdn")


def _initial_status_from_action(action: str) -> str:
    from app.repositories.security_response_repository import (
        _initial_status_from_action as resolve_status,
    )

    return resolve_status(action)


def test_log_and_alert_response_are_recorded():
    assert _initial_status_from_action("LOG") == "RECORDED"
    assert _initial_status_from_action("ALERT") == "RECORDED"
    assert _initial_status_from_action("MONITOR") == "RECORDED"


def test_flow_action_response_stays_pending():
    assert _initial_status_from_action("RATE_LIMIT") == "PENDING"
    assert _initial_status_from_action("DROP") == "PENDING"
