class FlowRepository:
    def list_flows(self, src_ip: str | None = None) -> list[dict]:
        flows = [
            {
                "timestamp": "2026-05-24T10:00:00+09:00",
                "src_ip": "52.182.143.209",
                "dst_ip": "172.30.1.3",
                "protocol": "TCP",
                "packet_count": 16,
                "byte_count": 10149,
            }
        ]

        if src_ip:
            return [
                flow
                for flow in flows
                if flow["src_ip"] == src_ip
            ]

        return flows
