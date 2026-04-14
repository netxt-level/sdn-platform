# 파이썬 3.11 
FROM python:3.11-slim

# Scapy에 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# 컨테이너 내 작업 디렉토리 설정
WORKDIR /app

# 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스코드 복사
COPY . .

# FastAPI 서버 실행
CMD ["uvicorn","main:app","--host", "0.0.0.0","--port", "8000"]

