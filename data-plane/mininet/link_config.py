"""Pure parsing and validation for configurable Mininet transit links."""

import math
import re


CONFIGURABLE_LINKS = frozenset({
    "s1-s2",
    "s1-s3",
    "s2-s4",
    "s3-s4",
})
DELAY_PATTERN = re.compile(r"^(?:0|[0-9]+(?:\.[0-9]+)?)(?:us|ms|s)$")
SUPPORTED_PARAMETERS = frozenset({"bw", "delay", "loss"})


def canonical_link_name(first, second):
    """Return one deterministic name for a bidirectional link."""
    if not first or not second or first == second:
        raise ValueError(f"invalid link endpoints: {first}-{second}")
    return "-".join(sorted((first, second)))


def parse_link_config(specification):
    """Parse LINK:bw=N,delay=Nms,loss=N into TCLink parameters."""
    link_text, separator, parameter_text = specification.partition(":")
    if not separator or not link_text or not parameter_text:
        raise ValueError(
            "link config must use LINK:key=value[,key=value]"
        )

    endpoints = link_text.lower().split("-")
    if len(endpoints) != 2:
        raise ValueError(f"invalid link name: {link_text}")
    link_name = canonical_link_name(*endpoints)
    if link_name not in CONFIGURABLE_LINKS:
        raise ValueError(f"unknown configurable link: {link_name}")

    parameters = {}
    for assignment in parameter_text.split(","):
        key, assignment_separator, raw_value = assignment.partition("=")
        key = key.strip().lower()
        raw_value = raw_value.strip().lower()
        if not assignment_separator or not key or not raw_value:
            raise ValueError(f"invalid link parameter: {assignment}")
        if key not in SUPPORTED_PARAMETERS:
            raise ValueError(f"unsupported link parameter: {key}")
        if key in parameters:
            raise ValueError(f"duplicate link parameter: {key}")

        if key == "delay":
            if not DELAY_PATTERN.fullmatch(raw_value):
                raise ValueError(f"invalid link delay: {raw_value}")
            parameters[key] = raw_value
            continue

        try:
            numeric_value = float(raw_value)
        except ValueError as error:
            raise ValueError(
                f"invalid link {key}: {raw_value}"
            ) from error
        if not math.isfinite(numeric_value):
            raise ValueError(f"invalid link {key}: {raw_value}")
        if key == "bw" and numeric_value <= 0:
            raise ValueError("link bandwidth must be greater than zero")
        if key == "loss" and not 0 <= numeric_value <= 100:
            raise ValueError("link loss must be between 0 and 100")
        parameters[key] = numeric_value

    return link_name, parameters


def parse_link_configs(specifications):
    """Parse repeated CLI specifications and reject duplicate links."""
    configurations = {}
    for specification in specifications:
        link_name, parameters = parse_link_config(specification)
        if link_name in configurations:
            raise ValueError(f"duplicate link config: {link_name}")
        configurations[link_name] = parameters
    return configurations


def delay_to_milliseconds(delay):
    """Convert a validated TCLink delay string into milliseconds."""
    if not DELAY_PATTERN.fullmatch(delay):
        raise ValueError(f"invalid link delay: {delay}")

    if delay.endswith("us"):
        return float(delay[:-2]) / 1000
    if delay.endswith("ms"):
        return float(delay[:-2])
    return float(delay[:-1]) * 1000
