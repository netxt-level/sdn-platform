from fastapi import APIRouter

router = APIRouter()

@router.get("/summary")
def get_dashboard_summary():
    return {
        "total_packets": 12000,
        "total_bytes": 8892301,
        "current_pps": 90.0,
        "current_bps": 273960.0,
        "network_status": "normal",
    }

@router.get("/protocols")
def get_protocols():
    return {
        "items": [
            {
                "protocol": "TCP",
                "packet_count": 8700,
                "percentage": 96.7,
            },
            {
                "protocol": "UDP",
                "packet_count": 200,
                "percentage": 2.2,
            },
        ],
    }