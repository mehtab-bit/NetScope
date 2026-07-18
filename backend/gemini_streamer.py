import os
import json
import time
from typing import List, Dict, Generator
import google.generativeai as genai

class GeminiStreamer:
    """
    Orchestrates AI-powered network analysis with a robust fallback chain:
    1. Google Gemini SDK (primary)
    2. OpenRouter free-tier models (cascade)
    3. Local rule-based analysis (offline)
    """
    
    SYSTEM_INSTRUCTION = """
You are NetScope Packet Assistant, an expert, friendly network security engineer and AI assistant.
Your goal is to help beginners understand network packet captures (PCAP traces) without getting overwhelmed by technical jargon.

When explaining, follow these rules:
1. Be extremely clear, encouraging, and easy to understand. Translate terms like "5-tuple", "TCP Handshake", "SYN", "SNI", and "ports" into simple analogies (e.g., "a port is like a specific mail slot in a building").
2. Summarize the traffic overview (e.g., "This trace shows a person visiting YouTube and Google, using about 5MB of data").
3. Point out security risks or anomalies in plain English. For example, if a port scan is detected, explain what it is and why it's suspicious, but keep the tone calm and educational.
4. Recommend firewalls or blocking rules using the C++ DPI format. Example formatting:
   - To block YouTube: --block-app YouTube
   - To block an IP: --block-ip 192.168.1.222
5. Render your responses in structured Markdown with bullet points, bold text, and clean formatting.
"""

    # Ordered list of free OpenRouter models to cascade through
    OPENROUTER_FREE_MODELS = [
        "google/gemini-2.0-flash-exp:free",
        "meta-llama/llama-4-maverick:free",
        "mistralai/mistral-small-3.1-24b-instruct:free",
        "qwen/qwen3-8b:free",
    ]

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model_name = "gemini-2.5-flash"
        self.initialized = False
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(
                    model_name=self.model_name,
                    system_instruction=self.SYSTEM_INSTRUCTION
                )
                self.initialized = True
            except Exception as e:
                print(f"[NetScope] Gemini SDK init failed: {e}")
                self.initialized = False

    def stream_analysis(self, flows: List[dict], user_query: str = None, chat_history: List[dict] = None) -> Generator[str, None, None]:
        """
        Generates a streaming markdown response. Fallback chain:
        Gemini SDK → OpenRouter free models → Local offline analysis.
        """
        # Build context from flow data
        flow_summary = []
        threats_detected = 0
        total_bytes = 0
        total_packets = 0
        
        for f in flows:
            total_bytes += f["byte_count"]
            total_packets += f["packet_count"]
            anom = f.get("anomalies", [])
            if anom:
                threats_detected += len(anom)
                
            flow_summary.append({
                "flow_id": f["flow_id"],
                "source": f["src_ip"],
                "destination": f["dst_ip"],
                "protocol": f["protocol"],
                "port": f["dst_port"],
                "category": f["app_category"],
                "domain": f["domain"],
                "bytes": f["byte_count"],
                "packets": f["packet_count"],
                "duration_sec": f["duration"],
                "anomalies": anom
            })
            
        context = {
            "overview": {
                "total_flows": len(flows),
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "threats_or_anomalies_found": threats_detected
            },
            "flows": flow_summary[:30]
        }
        
        # Build prompt
        if user_query:
            prompt = f"The user is asking: '{user_query}'\n\nHere is the network traffic data context:\n{json.dumps(context, indent=2)}"
        else:
            prompt = f"Please provide an introductory, beginner-friendly summary of this network traffic capture. Here is the flow data:\n{json.dumps(context, indent=2)}"
            
        # === FALLBACK CHAIN ===
        
        # 1. Try Gemini SDK
        if self.initialized:
            try:
                contents = []
                if chat_history:
                    for msg in chat_history[-6:]:
                        role = "user" if msg["role"] == "user" else "model"
                        contents.append({"role": role, "parts": [msg["content"]]})
                
                contents.append({"role": "user", "parts": [prompt]})
                response = self.model.generate_content(contents, stream=True)
                
                for chunk in response:
                    if chunk.text:
                        yield f"data: {json.dumps({'text': chunk.text})}\n\n"
                        
                yield "data: [DONE]\n\n"
                return  # Success — exit here
            except Exception as e:
                print(f"[NetScope] Gemini API call failed: {e}")
                yield f"data: {json.dumps({'text': '⚠️ Gemini API unavailable, switching to backup provider...'})}\n\n"
        
        # 2. Try OpenRouter free model cascade
        or_key = os.environ.get("OPENROUTER_API_KEY", "")
        if or_key:
            for model_id in self.OPENROUTER_FREE_MODELS:
                try:
                    print(f"[NetScope] Trying OpenRouter model: {model_id}")
                    success = yield from self._stream_openrouter(prompt, or_key, model_id, chat_history)
                    if success:
                        return  # Success — exit here
                except ValueError as ve:
                    if str(ve) == "402_PAYMENT_REQUIRED":
                        yield f"data: {json.dumps({'text': '⚠️ **API Key Depleted**: OpenRouter returned HTTP 402 (Payment Required). The free models might be overloaded or disabled for this key.'})}\n\n"
                        break # Stop trying other models
                except Exception as e:
                    print(f"[NetScope] OpenRouter model {model_id} failed: {e}")
                    continue
        
        # 3. Local offline analysis (last resort)
        yield f"data: {json.dumps({'text': '> **Note:** Falling back to robust local traffic analysis...'})}\n\n"
        yield f"data: {json.dumps({'text': chr(10) + chr(10)})}\n\n"
        yield from self._stream_fallback(flows, user_query)

    def _stream_openrouter(self, prompt: str, api_key: str, model_id: str, chat_history: List[dict] = None) -> Generator:
        """Streams from a single OpenRouter model. Returns True via generator if successful."""
        import urllib.request
        
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "NetScope Packet Analyzer"
        }
        
        messages = [{"role": "system", "content": self.SYSTEM_INSTRUCTION}]
        if chat_history:
            for msg in chat_history[-6:]:
                role = "user" if msg["role"] == "user" else "assistant"
                messages.append({"role": role, "content": msg["content"]})
                
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": model_id,
            "messages": messages,
            "stream": True
        }
        
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers=headers,
            method="POST"
        )
        
        try:
            response = urllib.request.urlopen(req, timeout=30)
            got_content = False
            for line in response:
                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue
                if line_str.startswith("data: "):
                    event_data = line_str[6:].strip()
                    if event_data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(event_data)
                        # Check for error responses embedded in stream
                        if "error" in chunk:
                            print(f"[NetScope] OpenRouter stream error: {chunk['error']}")
                            return False
                        content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if content:
                            got_content = True
                            yield f"data: {json.dumps({'text': content})}\n\n"
                    except Exception:
                        pass
            
            if got_content:
                yield "data: [DONE]\n\n"
                return True
            return False
            
        except urllib.error.HTTPError as e:
            print(f"[NetScope] OpenRouter HTTP {e.code} for {model_id}")
            if e.code == 402:
                raise ValueError("402_PAYMENT_REQUIRED")
            return False
        except Exception as e:
            print(f"[NetScope] OpenRouter error for {model_id}: {e}")
            return False

    def _stream_fallback(self, flows: List[dict], query: str = None) -> Generator[str, None, None]:
        """Local rule-based analysis using parsed flow data. No AI required."""
        # Count stats from actual flows
        threats = []
        protocols = {}
        total_bytes = 0
        domains = []
        
        for f in flows:
            total_bytes += f.get("byte_count", 0)
            proto = f.get("protocol", "Unknown")
            protocols[proto] = protocols.get(proto, 0) + 1
            if f.get("anomalies"):
                threats.extend(f["anomalies"])
            if f.get("domain"):
                domains.append(f["domain"])
                
        unique_domains = list(set(domains))[:5]
        
        if len(flows) == 0:
            explanation = """### Traffic Analysis Report

> No flow data is currently loaded. Upload a `.pcap` file or select a demo capture from the sidebar to begin analysis.
"""
        else:
            threat_section = ""
            if threats:
                threat_section = f'🚨 **{len(threats)} Warning(s) Detected**: ' + ', '.join(set(threats))
            else:
                threat_section = '✅ **No security anomalies detected.** All flows match expected patterns.'
            
            proto_section = ", ".join([f"**{k}** ({v} flows)" for k, v in protocols.items()])
            domain_section = ', '.join(unique_domains) if unique_domains else 'no domains resolved'
            
            explanation = f"""### Traffic Analysis Report

**Summary**: Analyzed **{len(flows)} network conversations** totaling **{total_bytes / 1024:.1f} KB** of traffic.

**Protocol Breakdown**: {proto_section}

**Detected Domains**: {domain_section}

**Security Assessment**: {threat_section}

---

**Key Concepts:**
- A **flow** is a complete conversation between two computers identified by source IP, destination IP, and their ports.
- **DNS** queries translate domain names (like `google.com`) into IP addresses.
- **TLS/HTTPS** connections are encrypted, but the domain name is visible in the initial handshake (SNI).

**DPI Engine Rules** — to filter this traffic with the C++ engine:
- `--block-app YouTube` — drop streaming packets
- `--block-ip <suspicious_ip>` — block a specific machine
- `--block-domain <domain>` — block by domain substring
"""
        
        # Stream word-by-word
        words = explanation.split(" ")
        chunk_size = 6
        
        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i+chunk_size]) + " "
            yield f"data: {json.dumps({'text': chunk})}\n\n"
            time.sleep(0.03)
            
        yield "data: [DONE]\n\n"
