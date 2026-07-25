"""Thread-safe allocation and reference tracking for OVS meters."""

from dataclasses import dataclass
import hashlib
from threading import RLock


MAX_ALLOCATABLE_METER_ID = 0x7FFFFFFF


@dataclass(frozen=True)
class MeterLease:
    dpid: int
    meter_id: int
    rate_limit_pps: int
    created: bool


@dataclass
class _MeterRecord:
    rate_limit_pps: int
    rule_ids: set[str]


class MeterRegistry:
    """Reuse compatible meters and release them after the final rule."""

    def __init__(self):
        self._meters = {}
        self._rule_meters = {}
        self._lock = RLock()

    def allocate(self, dpid, rule_id, rate_limit_pps):
        self._validate(dpid, rule_id, rate_limit_pps)
        rule_key = (dpid, rule_id)
        with self._lock:
            existing_meter_id = self._rule_meters.get(rule_key)
            if existing_meter_id is not None:
                record = self._meters[(dpid, existing_meter_id)]
                if record.rate_limit_pps != rate_limit_pps:
                    raise ValueError(
                        "existing rule cannot change rate_limit_pps"
                    )
                return MeterLease(
                    dpid=dpid,
                    meter_id=existing_meter_id,
                    rate_limit_pps=rate_limit_pps,
                    created=False,
                )

            for (meter_dpid, meter_id), record in self._meters.items():
                if (
                    meter_dpid == dpid
                    and record.rate_limit_pps == rate_limit_pps
                ):
                    record.rule_ids.add(rule_id)
                    self._rule_meters[rule_key] = meter_id
                    return MeterLease(
                        dpid=dpid,
                        meter_id=meter_id,
                        rate_limit_pps=rate_limit_pps,
                        created=False,
                    )

            meter_id = self._next_meter_id(dpid, rate_limit_pps)
            self._meters[(dpid, meter_id)] = _MeterRecord(
                rate_limit_pps=rate_limit_pps,
                rule_ids={rule_id},
            )
            self._rule_meters[rule_key] = meter_id
            return MeterLease(
                dpid=dpid,
                meter_id=meter_id,
                rate_limit_pps=rate_limit_pps,
                created=True,
            )

    def release(self, dpid, rule_id):
        """Release one rule and return a meter ID only when it became unused."""
        with self._lock:
            meter_id = self._rule_meters.pop((dpid, rule_id), None)
            if meter_id is None:
                return None
            meter_key = (dpid, meter_id)
            record = self._meters[meter_key]
            record.rule_ids.discard(rule_id)
            if record.rule_ids:
                return None
            del self._meters[meter_key]
            return meter_id

    def release_datapath(self, dpid):
        """Forget all meter state when a switch disconnects."""
        with self._lock:
            meter_ids = tuple(
                meter_id
                for meter_dpid, meter_id in self._meters
                if meter_dpid == dpid
            )
            for meter_id in meter_ids:
                record = self._meters.pop((dpid, meter_id))
                for rule_id in record.rule_ids:
                    self._rule_meters.pop((dpid, rule_id), None)
            return tuple(sorted(meter_ids))

    def snapshot(self):
        with self._lock:
            return tuple(
                {
                    "dpid": dpid,
                    "meter_id": meter_id,
                    "rate_limit_pps": record.rate_limit_pps,
                    "rule_ids": tuple(sorted(record.rule_ids)),
                }
                for (dpid, meter_id), record in sorted(self._meters.items())
            )

    def _next_meter_id(self, dpid, rate_limit_pps):
        digest = hashlib.blake2s(
            f"{dpid}:{rate_limit_pps}".encode("ascii"),
            digest_size=4,
        ).digest()
        candidate = int.from_bytes(digest, "big") & MAX_ALLOCATABLE_METER_ID
        candidate = max(1, candidate)
        while (dpid, candidate) in self._meters:
            candidate = 1 if candidate >= MAX_ALLOCATABLE_METER_ID else candidate + 1
        return candidate

    @staticmethod
    def _validate(dpid, rule_id, rate_limit_pps):
        if isinstance(dpid, bool) or not isinstance(dpid, int) or dpid < 0:
            raise ValueError("dpid must be a non-negative integer")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        if (
            isinstance(rate_limit_pps, bool)
            or not isinstance(rate_limit_pps, int)
            or rate_limit_pps <= 0
        ):
            raise ValueError("rate_limit_pps must be a positive integer")
