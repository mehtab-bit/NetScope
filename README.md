# NetScope.ai — Intelligent Network Packet Analyzer

NetScope.ai is a full-stack, AI-powered network packet inspection and diagnostics dashboard. It enables networking beginners and security analysts to upload standard `.pcap` files, reconstruct packet conversations (flows), classify traffic using local Machine Learning, and interact with a Generative AI packet assistant to identify anomalies and secure networks.

Originally started as a multi-threaded C++ CLI Deep Packet Inspection (DPI) engine, the project has been evolved into a premium, responsive Web Application ready for containerized cloud deployment on AWS.

---

## 🚀 Key Features

*   **DPI Parser Engine**: Fully decodes binary packet captures, extracting Layer 2-7 protocols including Ethernet, IPv4, TCP, UDP, DNS queries, HTTP host headers, and TLS Server Name Indication (SNI) handshakes.
*   **Local Machine Learning Classifier**: Employs a local Random Forest classifier alongside statistical heuristic rules to classify network flows into *Streaming Media*, *Web Browsing*, *File Transfers*, or *Chat/Interactive*, and flags security threats like *Port Scans* or data exfiltrations.
*   **Generative AI Streaming Assistant**: Integrates with Google Gemini (via Server-Sent Events) to stream plain-English network summaries, translate complex networking jargon, and generate firewall/blocking rules (C++ DPI formats).
*   **Beginner Onboarding**: Welcomes new users with a 3-step interactive tour guide explaining networking fundamentals (flows, ports, DNS) and includes pre-loaded interactive simulations for instant analysis.
*   **Premium Responsive SPA**: Built with a dark glassmorphic layout, staggered entrance animations, and responsive side drawers optimized for both desktop and mobile screens.
*   **AWS App Runner Deployment**: Containerized with a working `Dockerfile` optimized for public cloud deployments with zero-secrets configuration.

---

## 🛠️ Technology Stack

*   **Frontend**: Vanilla HTML5 (Semantic Structure), Vanilla CSS3 (Glassmorphic variables, fluid media queries, custom animations), Vanilla ES6 JavaScript.
*   **Backend Server**: Python 3.10+ with **FastAPI** for high-performance API routing and async streaming response generators.
*   **Machine Learning**: Scikit-Learn (**RandomForestClassifier**), NumPy, Pandas.
*   **AI Integration**: **Google GenAI SDK** (Gemini 2.5 Flash model) with streaming SSE callbacks and local fallback generators for offline capability.
*   **Deployment**: Docker, AWS App Runner.

---

## 📂 File Structure

```
Packet_analyzer/
├── frontend/                   # Single Page Application Frontend
│   ├── index.html              # Glassmorphic structure & Onboarding card
│   ├── style.css               # Responsive stylesheet & animations
│   └── app.js                  # SSE chat streams, counters, charts, & CSV export
│
├── backend/                    # FastAPI Backend Server
│   ├── main.py                 # Core API endpoints & health checks
│   ├── pcap_parser.py          # Python PCAP binary header decoder
│   ├── traffic_classifier.py   # ML Random Forest flow categorizer
│   ├── gemini_streamer.py      # SSE generator for Gemini AI / static fallbacks
│   └── demo_pcaps/             # Preloaded simulation captures for beginners
│
├── src/                        # Original C++ CLI Engine (Reference)
│   ├── pcap_reader.cpp         # Raw PCAP reader
│   ├── packet_parser.cpp       # Binary network byte packet parser
│   ├── sni_extractor.cpp       # Plaintext TLS SNI / HTTP Host header extractor
│   └── dpi_mt.cpp              # Multi-threaded orchestrator (LBs + FPs)
│
├── Dockerfile                  # Container specifications for AWS
├── requirements.txt            # Python dependencies mapping
└── README.md                   # This file!
```

---

## 💻 Local Quick Start (Web Application)

### 1. Install Prerequisites
Make sure you have Python 3.8+ installed.

### 2. Set Up Virtual Environment & Dependencies
Open your shell in the project folder and run:
```powershell
# Create virtual environment
python -m venv .venv_pcap

# Activate virtual environment (Windows PowerShell)
.\.venv_pcap\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt
```

### 3. Start the Server
Run the FastAPI application with Uvicorn:
```powershell
python -m uvicorn backend.main:app --port 8000
```
Open your browser and navigate to: **[http://localhost:8000/](http://localhost:8000/)**

---

## 🐳 Dockerization & AWS Deployment

### 1. Build and Run Container Locally
You can package the full stack into a single self-contained image:
```bash
# Build the image
docker build -t netscope-analyzer .

# Run the container (inject your Gemini API key as an environment variable)
docker run -p 8000:8000 -e GEMINI_API_KEY="your_actual_key_here" netscope-analyzer
```
Go to `http://localhost:8000/` to test.

### 2. Deploy to AWS App Runner
AWS App Runner provides fully managed container deployments:
1.  Push the Docker image to **AWS Elastic Container Registry (ECR)**.
2.  Create an **AWS App Runner Service** pointing to the ECR image repository.
3.  Configure the environment variable `GEMINI_API_KEY` inside the App Runner console configuration settings.
4.  AWS App Runner will automatically deploy the container, map ports, configure SSL/HTTPS, and serve the application live under a public domain URL.

---

## ⚙️ Historical C++ CLI Engine

The core C++ parsing and load-balancing algorithms are retained in the `src/` directory for reference or compilation:

### Build CLI Engine:
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Run CLI Engine:
```bash
./dpi_engine input.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
```

---

## 🛡️ Security Best Practices

1.  **Zero client secrets**: All communication with the Gemini API happens server-side. The frontend never accesses or leaks the API keys.
2.  **Flexible Configuration**: You can configure your Gemini key either by passing it as a runtime environment variable (`GEMINI_API_KEY`) on the server host, or temporarily typing it into the sidebar input field (saved only in local browser `localStorage`).
3.  **Temporary Storage Isolation**: Uploaded `.pcap` files are written to safe temporary system files and securely garbage-collected/deleted immediately after extraction to prevent memory leaks or file retention.
