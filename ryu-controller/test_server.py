from fastapi import FastAPI
import uvicorn

app = FastAPI()

# 선빈이 명세서 규격과 똑같은 엔드포인트 개방
@app.post("/api/backend/analyzer/packet-summary")
async def receive_packet(data: dict):
    print("\n🔥 [가짜 백엔드] Ryu 컨트롤러로부터 데이터 수신 성공!")
    print(f"   출발지 IP: {data['host_stats'][0]['src_ip']}")
    print(f"   목적지 IP: {data['host_stats'][0]['dst_ip']}")
    print(f"   패킷 크기: {data['total_bits']} bits")
    return {"success": True, "message": "패킷 요약 정보 수신 완료"}
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)