FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV CONTROLLER_OPENFLOW_PORT=6653

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && python -c "import os_ken; from os_ken.ofproto import ofproto_v1_3; assert ofproto_v1_3.OFP_VERSION == 0x04" \
    && osken-manager --version

COPY app ./app

EXPOSE 6653

CMD ["sh", "-c", "exec osken-manager --ofp-tcp-listen-port \"$CONTROLLER_OPENFLOW_PORT\" app/controller.py"]
