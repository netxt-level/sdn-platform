from __future__ import annotations

import argparse
import json
from pathlib import Path

from .backend_contract import result_to_backend_payload
from .engine import SecurityAnalysisEngine
from .io import load_security_input
from .ryu_adapter import flow_rules_from_policies


def main() -> int:
    """저장된 시나리오 파일로 보안 엔진을 독립 실행한다."""

    parser = argparse.ArgumentParser(description="Run an SDN security scenario sample.")
    parser.add_argument("--input", required=True, help="Scenario JSON path.")
    parser.add_argument("--datapath-id", default="s1", help="Datapath id for flow-rule output.")
    parser.add_argument("--backend-out", help="Optional backend payload output path.")
    parser.add_argument("--flow-out", help="Optional flow-rule output path.")
    args = parser.parse_args()

    packets, links, baseline, config = load_security_input(args.input)
    # 실제 capture 없이도 샘플 패킷부터 정책 후보까지 같은 경로를 검증한다.
    result = SecurityAnalysisEngine(config=config, baseline=baseline).analyze(
        packets,
        links=links,
    )
    backend_payload = result_to_backend_payload(result)
    flow_payload = {
        # Controller가 받을 수 있는 형태를 별도 파일로 확인할 수 있게 분리한다.
        "flow_rules": flow_rules_from_policies(
            result.policies,
            datapath_id=args.datapath_id,
        ),
    }

    if args.backend_out:
        _write_json(args.backend_out, backend_payload)
    if args.flow_out:
        _write_json(args.flow_out, flow_payload)

    print(json.dumps(backend_payload, ensure_ascii=False, indent=2))
    return 0


def _write_json(path: str, payload: dict[str, object]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
