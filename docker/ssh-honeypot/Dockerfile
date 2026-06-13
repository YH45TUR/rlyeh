# R'lyeh - SSH Honeypot container
FROM python:3.11-slim

LABEL maintainer="rlyeh-honeypot"
LABEL description="R'lyeh SSH Honeypot"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN useradd -m -u 1000 honeypot
USER honeypot

ENV HONEYPOT_BIND_HOST=0.0.0.0
ENV HONEYPOT_BIND_PORT=2222
ENV HONEYPOT_LOG_DIR=/var/log/rlyeh

EXPOSE 2222

CMD ["python", "-m", "src.honeypots.ssh_honeypot"]
