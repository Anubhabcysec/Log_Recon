# LogRecon

> AI-powered threat intelligence and incident response platform

[![Live Demo](https://img.shields.io/badge/Live_Demo-log--recon.onrender.com-success?style=for-the-badge&logo=render)](https://log-recon.onrender.com)

---

## What It Does

LogRecon is a full-stack cybersecurity platform that combines real-time IP reputation analysis, vulnerability scanning, AI-powered log forensics, and correlated threat intelligence into a single unified dashboard. Built for SOC analysts and security-conscious individuals who want actionable intelligence without enterprise pricing.

---

## Features

- **IP Threat Analysis** — AbuseIPDB + Shodan live data, MITRE ATT&CK mapping
- **Local System Scanner** — Nmap port discovery, NVD CVE correlation, EPSS scores
- **Log Analyzer** — SSH, nginx, Apache, syslog, Windows Event Log support with Groq AI
- **Correlated Findings** — Cross-references scan data with log evidence into one verdict
- **Scan History & Change Detection** — Detects newly opened ports since last scan
- **Alert Center** — Rule-based alerts for RDP exposure, brute force, critical CVEs
- **Asset Inventory** — Track authorized systems, detect unauthorized IPs
- **Telegram Alerts** — Configurable severity threshold notifications
- **PDF Reports** — Downloadable security assessment reports
- **Live Terminal Stream** — Real-time scan output in browser

---

## Tech Stack

- **Backend:** Python, Flask, SQLAlchemy, SQLite
- **APIs:** AbuseIPDB, Shodan, NVD NIST, Groq AI, First.org EPSS
- **Scanner:** Nmap via python-nmap
- **Frontend:** HTML, CSS, JavaScript, Three.js

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/your-username/automated-ir-tool.git
cd automated-ir-tool
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Create `.env` file
Create a `.env` file in the root directory and configure your keys:
```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SHODAN_API_KEY=your_shodan_api_key
GROQ_API_KEY=your_groq_api_key
NVD_API_KEY=your_nvd_api_key
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id
SECRET_KEY=your_secret_key
```

### 4. Run the application
```bash
python app.py
```

### 5. Access the dashboard
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## API Keys Needed

To enable the full intelligence pipeline, obtain free API keys from the following providers:

- **AbuseIPDB:** [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
- **Shodan:** [https://account.shodan.io/register](https://account.shodan.io/register)
- **Groq:** [https://console.groq.com](https://console.groq.com)
- **NVD NIST:** [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

---

## Deployment Note

> **Note:** The live demo runs on Render free tier. Local scanning and Nmap features require running locally.

---

## Disclaimer

Built for educational and portfolio purposes. Only scan systems you own or have explicit permission to scan.

---

## Author

**Anubhab Das** — cybersecurity learner building toward SOC/Blue Team role
