# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS SPECTER PRO — Dockerfile                             ║
# ║  by OPTIMIUM NEXUS LLC                                      ║
# ╚══════════════════════════════════════════════════════════════╝

FROM kalilinux/kali-rolling:latest

LABEL maintainer="contact@optimiumnexus.com"
LABEL version="1.0.0-SPECTER"
LABEL description="NEXUS SPECTER PRO — Military-Grade Pentest Platform"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# ─── System Dependencies ─────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3-pip python3-dev \
    nmap masscan \
    nikto sqlmap \
    hydra medusa \
    curl wget git \
    libpq-dev \
    wkhtmltopdf \
    gobuster \
    dnsutils \
    netcat-openbsd \
    whois \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ─── Go Tools ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y golang-go && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    cp ~/go/bin/* /usr/local/bin/ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ─── Python Dependencies ─────────────────────────────────────────
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ─── Application Code ────────────────────────────────────────────
COPY . .

RUN pip3 install -e .

# ─── Update Nuclei Templates ─────────────────────────────────────
RUN nuclei -update-templates -silent || true

# ─── Entrypoint ──────────────────────────────────────────────────
EXPOSE 8080
ENTRYPOINT ["python3", "nsp_cli.py"]
CMD ["--help"]
