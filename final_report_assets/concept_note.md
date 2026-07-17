# Project Concept Note: NetScope.ai

## 1. Metadata
*   **Project Title:** NetScope.ai - Intelligent Conversational Network Analyzer
*   **Application Name:** NetScope.ai
*   **API / LLM Model Used:** Google Gemini 2.5 Flash via `google-generativeai` SDK (Streaming mode)
*   **Live Application URL:** `https://[YOUR-APP-RUNNER-URL].awsapprunner.com` (Placeholder for AWS Deploy)

---

## 2. Executive Summary
Network analysis is traditionally a highly technical domain confined to specialized engineers who understand TCP dumps, packet headers, and hexadecimal streams. Non-technical stakeholders, students, and beginners are completely locked out of diagnosing network performance, validating security profiles, or discovering traffic anomalies. 

**NetScope.ai** is an AI-powered, single-container full-stack web application designed to democratize packet inspection. By blending **local Machine Learning flow classification** with **streaming Generative AI explanations**, it translates raw Wireshark network captures (`.pcap` traces) into plain English insights. 

---

## 3. Problem Statement & Objectives
1.  **High Barrier to Entry:** Beginners cannot interpret raw Wireshark statistics or hexadecimal bytes. NetScope.ai aims to translate networking jargon into simple, real-world analogies (e.g. comparing "ports" to "mail slots").
2.  **Lack of Safe Testing Data:** Beginners often do not have toolsets to capture network traffic safely. NetScope.ai addresses this by including **One-Click Demo Traces** (safe browsing, heavy streaming, and active port scanning) to allow instant analysis.
3.  **Static, Non-Interactive Reports:** Traditional traffic reports are static summaries. NetScope.ai implements a **real-time streaming chat assistant** where users can directly "chat" with their network data.

---

## 4. Key Target Users & Use Cases
*   **Cybersecurity Students:** Understanding how scan payloads, DNS requests, and secure vs. plaintext websites present themselves in raw traffic.
*   **System Administrators:** Finding high-bandwidth devices or applications (e.g. YouTube vs. standard web browsing) and auto-generating C++ blocking rules.
*   **Home Users:** Discovering if any device on their local Wi-Fi network is running suspicious background activities.

---

## 5. Main Application Features
1.  **Binary PCAP Parsing:** A custom, pure Python parsing module that extracts Ethernet, IPv4, TCP, and UDP headers, and isolates TLS SNI, HTTP Host, and DNS queries.
2.  **Local RandomForest Machine Learning:** A local Random Forest classifier running on-server to label flows (Streaming, Browsing, Chat, File Transfer) based on statistical traffic features (packet sizes, count, bytes, duration).
3.  **Port Scan & Threat Detection Heuristics:** Scans for warning signs, such as a single IP attempting connections to more than 10 unique ports, flagging it instantly as a warning.
4.  **Generative AI Conversational Companion:** An interactive chat UI that streams conversational explanations of network packets via Gemini API using Server-Sent Events (SSE).
5.  **Interactive Cyberpunk Dashboard:** A visually stunning, dark-mode glassmorphic interface built with vanilla JS and HSL variables. Shows protocol distributions, top app consumers, and warning logs.
