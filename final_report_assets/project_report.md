# Vibe Coding Project Report: NetScope.ai

## 1. Application Overview & Tech Stack
NetScope.ai is a full-stack, containerized web application that serves as an intelligent diagnostic dashboard for raw network packet captures (`.pcap`).

### Tech Stack Details
*   **Backend Server:** **Python FastAPI**
    *   *Rationale:* High performance, natively handles async EventSource streams, and hosts data science libraries (Pandas, Scikit-Learn) with zero lag.
*   **Frontend Interface:** **Vanilla HTML5, CSS3 (Glassmorphic dark design), and JavaScript (ES6 SPA)**
    *   *Rationale:* Served directly by FastAPI to avoid cross-origin (CORS) resource complexity. Eliminates bulky NPM compilation pipelines, leading to a much smaller Docker image size and faster cloud build times.
*   **Local Machine Learning:** **Scikit-Learn (RandomForestClassifier)**
    *   *Rationale:* Automatically trains on-startup in under 0.1 seconds, eliminating the need to bundle massive serialized weight files in git or container layers.
*   **Generative AI Integration:** **Google Gemini 2.5 Flash** (via `google-generativeai` SDK)
    *   *Rationale:* Lowest response latency for conversational text streams.
*   **Containerization:** **Docker** (multi-stage, optimized `python:3.11-slim` build)
*   **Cloud Infrastructure Target:** **AWS App Runner** (Exposes port 8080 over HTTPS)

---

## 2. Architecture & Data Flow Diagram

```
[Raw PCAP / Demo PCAP]
       │
       ▼
┌───────────────────────────────┐
│   FastAPI Backend Server      │
│  ┌─────────────────────────┐  │
│  │ 1. PcapParser (Binary)  │  │  --> Decodes MACs, IPs, TCP/UDP, TLS SNI, HTTP Host
│  └───────────┬─────────────┘  │
│              ▼
│  ┌─────────────────────────┐  │
│  │ 2. RandomForest ML &    │  │  --> Classifies application category &
│  │    Threat Heuristics    │  │      flags scanning anomalies
│  └───────────┬─────────────┘  │
│              ▼
│  ┌─────────────────────────┐  │
│  │ 3. Gemini Streamer      │  │  --> Translates packet logs into prompt context;
│  │    (google-genai SDK)   │  │      streams SSE chunks
│  └───────────┬─────────────┘  │
└──────────────┼────────────────┘
               │ (Server-Sent Events Stream: data: {"text": "..."})
               ▼
┌────────────────────────────────┐
│   Vanilla JS Single-Page UI    │  --> Renders metrics, custom bars, chat history,
│   (index.html / style.css)     │      and parses streaming markdown in real-time
└────────────────────────────────┘
```

---

## 3. Prompt Engineering & AI System Design
To make NetScope.ai accessible to non-technical users, we engineered a specific system instruction for the Gemini Model:

### System Prompt Template
```markdown
You are Antigravity Packet Assistant, an expert, friendly network security engineer and AI assistant.
Your goal is to help beginners understand network packet captures (PCAP traces) without getting overwhelmed by technical jargon.

When explaining, follow these rules:
1. Be extremely clear, encouraging, and easy to understand. Translate terms like "5-tuple", "TCP Handshake", "SYN", "SNI", and "ports" into simple analogies (e.g., "a port is like a specific mail slot in a building").
2. Summarize the traffic overview (e.g., "This trace shows a person visiting YouTube and Google, using about 5MB of data").
3. Point out security risks or anomalies in plain English. For example, if a port scan is detected, explain what it is and why it's suspicious, but keep the tone calm and educational.
4. Recommend firewalls or blocking rules using the C++ DPI format. Example formatting:
   - To block YouTube: --block-app YouTube
   - To block an IP: --block-ip 192.168.1.222
5. Render your responses in structured Markdown with bullet points, bold text, and clean formatting.
```

---

## 4. Key Development Challenges & Resolutions

### Challenge 1: Cross-Origin Resource Sharing (CORS) & Cloud Deployment
*   *Problem:* Splitting the app into a React/Vite frontend and a separate FastAPI backend forces double-container deployments, requiring complex configuration for CORS headers and DNS endpoints in AWS.
*   *Resolution:* We structured the FastAPI backend to host and serve the static `frontend/` directory directly under the `/` path. This creates a unified single-container application. It compiles instantly, has zero CORS conflicts, and runs on AWS App Runner with a single deployment action.

### Challenge 2: Handling Missing Gemini API Keys
*   *Problem:* If the deployment doesn't have a configured API key, the chatbot and insights pane would break, leading to a poor user experience.
*   *Resolution:* We designed a **local static fallback stream** inside `backend/gemini_streamer.py`. If the API key is unconfigured, the app falls back to analyzing the flow metrics locally in Python, formatting a detailed static report, and streaming it word-by-word to the UI. This provides a graceful, educational fallback that instructs the user on how to add their key.

---

## 5. Reflections & Key Learnings
1.  **Vibe Coding Efficiency:** By focusing on Creative Direction and Systems Architecture, we went from a clean repository to a fully responsive, containerized network diagnostic tool in under an hour.
2.  **Aesthetic Value:** Incorporating dark themes, glassmorphism, dynamic SVG charts, and interactive suggestion chips greatly increases user confidence and software usability, especially for educational products.
3.  **AWS Deployment Simplicity:** Designing the app to run as a single Docker container listening on port 8080 makes AWS App Runner deployment a simple "point-and-build" task, eliminating complex VPC and load balancer configurations.
