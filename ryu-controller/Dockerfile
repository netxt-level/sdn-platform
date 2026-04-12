FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONPATH=/app
# 최신 pip에 의해 설치가 되지 않는 것 같아 구버전으로 고정 후 빌드 도구 설치
RUN pip install --no-cache-dir pip==22.3.1 setuptools==59.6.0 wheel

RUN pip install --no-cache-dir msgpack==0.6.2
RUN pip install --no-cache-dir eventlet==0.30.2
RUN pip install --no-cache-dir ryu==4.34
RUN pip install --no-cache-dir dnspython==1.16.0
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["ryu-manager", "app/myController.py"]