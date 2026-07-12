from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.policies.flow_rule_policy import (
    is_action_strong_enough,
    is_compatible_flow_rule,
    is_reusable_flow_rule,
)


def _flow_rule(**overrides):
    data = {
        "status": "PENDING",
        "hard_timeout": None,
        "applied_at": None,
        "created_at": None,
        "updated_at": None,
        "requested_at": None,
        "switch_id": None,
        "target": "flow",
        "action": "RATE_LIMIT",
        "match": {},
        "priority": 500,
        "rate_limit_pps": None,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_failed_flow_rule_is_not_reused():
    assert is_reusable_flow_rule(_flow_rule(status="FAILED")) is False


def test_pending_flow_rule_is_reused():
    assert is_reusable_flow_rule(_flow_rule(status="PENDING")) is True


def test_recent_pending_flow_rule_is_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    recent_rule = _flow_rule(
        status="PENDING",
        created_at=now - timedelta(minutes=9),
    )

    assert is_reusable_flow_rule(recent_rule, now=now) is True


def test_stale_pending_flow_rule_is_not_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    stale_rule = _flow_rule(
        status="PENDING",
        created_at=now - timedelta(minutes=11),
    )

    assert is_reusable_flow_rule(stale_rule, now=now) is False


def test_stale_applying_flow_rule_is_not_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    stale_rule = _flow_rule(
        status="APPLYING",
        requested_at=now - timedelta(minutes=6),
    )

    assert is_reusable_flow_rule(stale_rule, now=now) is False


def test_recent_applying_flow_rule_is_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    recent_rule = _flow_rule(
        status="APPLYING",
        requested_at=now - timedelta(minutes=4),
    )

    assert is_reusable_flow_rule(recent_rule, now=now) is True


def test_stale_dict_flow_rule_is_not_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    stale_rule = {
        "status": "PENDING",
        "created_at": now - timedelta(minutes=11),
    }

    assert is_reusable_flow_rule(stale_rule, now=now) is False


def test_expired_applied_flow_rule_is_not_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    expired_rule = _flow_rule(
        status="APPLIED",
        hard_timeout=30,
        applied_at=now - timedelta(seconds=31),
    )

    assert is_reusable_flow_rule(expired_rule, now=now) is False


def test_unexpired_applied_flow_rule_is_reused():
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    active_rule = _flow_rule(
        status="APPLIED",
        hard_timeout=30,
        applied_at=now - timedelta(seconds=29),
    )

    assert is_reusable_flow_rule(active_rule, now=now) is True


def test_applied_flow_rule_without_applied_at_is_not_reused():
    active_rule = _flow_rule(
        status="APPLIED",
        hard_timeout=30,
        applied_at=None,
    )

    assert is_reusable_flow_rule(active_rule) is False


def test_same_fingerprint_requires_same_switch_and_match():
    existing_rule = _flow_rule(
        switch_id="s1",
        match={"ipv4_src": "10.0.0.9", "ipv4_dst": "10.0.0.8"},
        rate_limit_pps=100,
    )
    requested_mitigation = {
        "switch_id": "s2",
        "target": "flow",
        "match": {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2"},
        "rate_limit_pps": 100,
    }

    assert is_compatible_flow_rule(
        existing_rule,
        requested_mitigation,
        requested_action="RATE_LIMIT",
    ) is False


def test_flow_reuse_compares_target_and_switch():
    existing_rule = _flow_rule(
        switch_id="s1",
        target="flow",
        match={"ipv4_src": "10.0.0.1"},
        rate_limit_pps=100,
    )

    assert is_compatible_flow_rule(
        existing_rule,
        {
            "switch_id": "s1",
            "target": "host",
            "match": {"ipv4_src": "10.0.0.1"},
            "rate_limit_pps": 100,
        },
        requested_action="RATE_LIMIT",
    ) is False


def test_weaker_rate_limit_is_not_reused():
    assert is_action_strong_enough(
        existing_action="RATE_LIMIT",
        requested_action="RATE_LIMIT",
        existing_rate_limit_pps=1000,
        requested_rate_limit_pps=100,
    ) is False


def test_stronger_rate_limit_can_be_reused():
    assert is_action_strong_enough(
        existing_action="RATE_LIMIT",
        requested_action="RATE_LIMIT",
        existing_rate_limit_pps=100,
        requested_rate_limit_pps=1000,
    ) is True


def test_drop_can_replace_rate_limit():
    assert is_action_strong_enough(
        existing_action="DROP",
        requested_action="RATE_LIMIT",
        existing_rate_limit_pps=None,
        requested_rate_limit_pps=100,
    ) is True


def test_lower_priority_rule_is_not_reused():
    existing_rule = _flow_rule(
        switch_id="s1",
        match={"ipv4_src": "10.0.0.2"},
        priority=100,
        rate_limit_pps=100,
    )

    assert is_compatible_flow_rule(
        existing_rule,
        {
            "switch_id": "s1",
            "target": "flow",
            "match": {"ipv4_src": "10.0.0.2"},
            "priority": 700,
            "rate_limit_pps": 100,
        },
        requested_action="RATE_LIMIT",
    ) is False


def test_shorter_timeout_rule_is_not_reused():
    existing_rule = _flow_rule(
        switch_id="s1",
        match={"ipv4_src": "10.0.0.2"},
        priority=700,
        idle_timeout=30,
        hard_timeout=30,
        rate_limit_pps=100,
    )

    assert is_compatible_flow_rule(
        existing_rule,
        {
            "switch_id": "s1",
            "target": "flow",
            "match": {"ipv4_src": "10.0.0.2"},
            "priority": 700,
            "idle_timeout": 60,
            "hard_timeout": 300,
            "rate_limit_pps": 100,
        },
        requested_action="RATE_LIMIT",
    ) is False


def test_permanent_timeout_request_does_not_reuse_finite_rule():
    existing_rule = _flow_rule(
        switch_id="s1",
        match={"ipv4_src": "10.0.0.2"},
        priority=700,
        idle_timeout=30,
        hard_timeout=30,
        rate_limit_pps=100,
    )

    assert is_compatible_flow_rule(
        existing_rule,
        {
            "switch_id": "s1",
            "target": "flow",
            "match": {"ipv4_src": "10.0.0.2"},
            "priority": 700,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "rate_limit_pps": 100,
        },
        requested_action="RATE_LIMIT",
    ) is False


def test_permanent_timeout_rule_can_cover_finite_request():
    existing_rule = _flow_rule(
        switch_id="s1",
        match={"ipv4_src": "10.0.0.2"},
        priority=700,
        idle_timeout=0,
        hard_timeout=0,
        rate_limit_pps=100,
    )

    assert is_compatible_flow_rule(
        existing_rule,
        {
            "switch_id": "s1",
            "target": "flow",
            "match": {"ipv4_src": "10.0.0.2"},
            "priority": 700,
            "idle_timeout": 60,
            "hard_timeout": 300,
            "rate_limit_pps": 100,
        },
        requested_action="RATE_LIMIT",
    ) is True
