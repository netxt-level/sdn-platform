FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ANALYZER_INTERFACE=eth0
ENV BACKEND_BASE_URL=http://host.docker.internal:8000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "app.main"]
