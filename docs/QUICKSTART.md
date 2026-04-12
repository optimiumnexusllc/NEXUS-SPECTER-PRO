# NEXUS SPECTER PRO — Quick Start Guide
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com

## 1. Install (Direct)
```bash
git clone https://github.com/optimiumnexusllc/NEXUS-SPECTER-PRO.git
cd NEXUS-SPECTER-PRO
pip install -r requirements.txt
cp .env.example .env && nano .env   # Add your API keys
python setup.py install
```

## 2. Deploy (Docker — Recommended)
```bash
cp .env.example .env && nano .env
docker-compose up -d
# Dashboard → http://localhost:8080
```

## 3. Run Missions
```bash
# Black Box
nsp --mode black_box --target example.com --output ./reports/

# Gray Box (authenticated)
nsp --mode gray_box --target example.com --creds config/creds.yaml

# Red Team (with AI)
nsp --mode red_team --target corp.local --ai-assist

# Cloud Audit
nsp --mode cloud_audit --provider aws

# List all modules
nsp --list-modules

# Dashboard
nsp --dashboard
```

## 4. Configure API Keys (.env)
| Key | Purpose |
|-----|---------|
| ANTHROPIC_API_KEY | Specter AI — attack planning + reporting |
| SHODAN_API_KEY | OSINT passive recon |
| CENSYS_API_ID/SECRET | Certificate + host intelligence |
| HUNTER_API_KEY | Email enumeration |
| HIBP_API_KEY | Breach data lookup |
| GITHUB_TOKEN | GitHub dorking (higher rate limits) |

## 5. Mission Templates
Located in `missions/` — copy and customize:
- `black_box.yaml` — Zero knowledge external test
- `gray_box.yaml` — Authenticated test
- `white_box.yaml` — Full knowledge deep dive
- `red_team.yaml` — Full adversarial simulation
- `cloud_audit.yaml` — AWS/Azure/GCP audit
