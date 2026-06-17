FROM python:3.11-slim

LABEL maintainer="PenToolbox v4.0"

RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    arp-scan \
    net-tools \
    iputils-ping \
    curl \
    git \
    perl \
    gcc \
    libffi-dev \
    hydra \
    libssl-dev \
    libnet-ssleay-perl \
    libcrypt-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    cpanminus \
    && rm -rf /var/lib/apt/lists/*

# Modules Perl manquants pour Nikto
RUN cpanm --notest JSON XML::Writer LWP::UserAgent HTTP::Request 2>/dev/null || true

# Nikto via git
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir sqlmap

COPY app.py .
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p reports
VOLUME ["/app/reports"]

EXPOSE 5000
ENV DOCKER_ENV=1

# Utilise le DNS de la machine hote Windows pour resoudre les hostnames locaux
# Le DNS host est automatiquement detecte par Docker Desktop sur Windows
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "app.py"]
