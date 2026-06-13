# R'lyeh - Web Honeypot container
FROM python:3.11-slim

LABEL maintainer="rlyeh-honeypot"
LABEL description="R'lyeh Web Honeypot"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN useradd -m -u 1000 honeypot
USER honeypot

ENV HONEYPOT_LOG_DIR=/var/log/rlyeh
ENV FLASK_ENV=production
ENV FLASK_PORT=8080

EXPOSE 8080

CMD ["python", "-m", "src.honeypots.web_honeypot"]
