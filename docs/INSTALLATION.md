# NEXUS SPECTER PRO — Installation Guide
by OPTIMIUM NEXUS LLC

## System Requirements
- **OS**: Kali Linux 2024+ / Ubuntu 22.04+ / ParrotOS
- **Python**: 3.12+
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 50GB minimum
- **Docker**: 24.0+ (for container deployment)

## External Tools (Auto-installed via Dockerfile)
- nmap, masscan, nikto, sqlmap, hydra, gobuster
- subfinder, httpx, nuclei, ffuf, assetfinder (Go)
- impacket, crackmapexec, enum4linux-ng
- bloodhound-python, neo4j

## Docker Deployment (Recommended)
```bash
git clone https://github.com/optimiumnexusllc/NEXUS-SPECTER-PRO.git
cd NEXUS-SPECTER-PRO
cp .env.example .env
# Edit .env with your API keys
docker-compose up -d
```
Services started:
- NSP Core Engine
- NSP Dashboard (port 8080)
- PostgreSQL database
- Redis queue
- Nuclei scanner
- Metasploit RPC

## Manual Installation (Kali Linux)
```bash
sudo apt update && sudo apt install -y python3.12 nmap masscan nikto sqlmap hydra
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
pip install -r requirements.txt
python setup.py install
```
