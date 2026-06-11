FROM python:3.11-slim

LABEL maintainer="PenToolbox v4.0"

# Outils réseau disponibles dans apt
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    arp-scan \
    net-tools \
    iputils-ping \
    curl \
    git \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Nikto via git (pas dans apt Debian Trixie)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# SQLMap via pip
RUN pip install --no-cache-dir sqlmap

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p reports
VOLUME ["/app/reports"]

EXPOSE 5000

ENV DOCKER_ENV=1

CMD ["python", "app.py"]
