import os
import json
import time
from typing import List, Dict, Generator
import google.generativeai as genai

class GeminiStreamer:
    """
    Orchestrates connection to Google Gemini API, formats network flow context,
    and returns a streaming generator for real-time explanations.
    """
    
    SYSTEM_INSTRUCTION = """
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
"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model_name = "gemini-2.5-flash"
        self.initialized = False
        
        # gen-lang-client is a Google Client/Project ID, not a valid API Key for SDK,
        # so we skip it to fallback instantly to OpenRouter without API configuration failure.
        if self.api_key and not self.api_key.startswith("gen-lang-client"):
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(
                    model_name=self.model_name,
                    system_instruction=self.SYSTEM_INSTRUCTION
                )
                self.initialized = True
            except Exception as e:
                print(f"Failed to initialize Gemini: {e}")
                self.initialized = False

    def stream_analysis(self, flows: List[dict], user_query: str = None, chat_history: List[dict] = None) -> Generator[str, None, None]:
        """
        Generates a streaming markdown response summarizing the network trace
        or answering user questions about the flows, formatted as SSE chunks.
        """
        # Formulate flow context
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
            "flows": flow_summary[:30] # Send first 30 flows to keep context window clean
        }
        
        # Build prompt
        prompt = ""
        if user_query:
            prompt = f"The user is asking: '{user_query}'\n\nHere is the network traffic data context:\n{json.dumps(context, indent=2)}"
        else:
            prompt = f"Please provide an introductory, beginner-friendly summary of this network traffic capture. Here is the flow data:\n{json.dumps(context, indent=2)}"
            
        if not self.initialized:
            # Try OpenRouter fallback first
            or_key = os.environ.get("OPENROUTER_API_KEY", "")
            if or_key and not or_key.startswith("your_"):
                yield from self._stream_openrouter(prompt, or_key, chat_history)
            else:
                yield from self._stream_fallback(flows, user_query)
            return

        try:
            # Build chat or content call
            contents = []
            if chat_history:
                for msg in chat_history[-6:]:  # include last 3 exchanges
                    role = "user" if msg["role"] == "user" else "model"
                    contents.append({"role": role, "parts": [msg["content"]]})
            
            contents.append({"role": "user", "parts": [prompt]})
            
            response = self.model.generate_content(contents, stream=True)
            
            for chunk in response:
                if chunk.text:
                    # Server-Sent Event formatting: "data: {text}"
                    yield f"data: {json.dumps({'text': chunk.text})}\n\n"
                    
            yield "data: [DONE]\n\n"
        except Exception as e:
            # Try OpenRouter fallback on runtime error
            or_key = os.environ.get("OPENROUTER_API_KEY", "")
            if or_key and not or_key.startswith("your_"):
                yield f"data: {json.dumps({'text': f'⚠️ Gemini API failed: {str(e)}. Attempting OpenRouter Fallback...' })}\n\n"
                yield from self._stream_openrouter(prompt, or_key, chat_history)
            else:
                yield f"data: {json.dumps({'text': f'⚠️ Gemini Error: {str(e)}. Falling back to local offline analysis.'})}\n\n"
                yield from self._stream_fallback(flows, user_query)

    def _stream_openrouter(self, prompt: str, api_key: str, chat_history: List[dict] = None) -> Generator[str, None, None]:
        """Streams AI explanation from OpenRouter using python built-in urllib library."""
        import urllib.request
        
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "NetScope AI Packet Analyzer"
        }
        
        messages = [{"role": "system", "content": self.SYSTEM_INSTRUCTION}]
        if chat_history:
            for msg in chat_history[-6:]:
                role = "user" if msg["role"] == "user" else "assistant"
                messages.append({"role": role, "content": msg["content"]})
                
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": "google/gemini-2.5-flash",
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
            response = urllib.request.urlopen(req, timeout=12)
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
                        content = chunk["choices"][0]["delta"].get("content", "")
                        if content:
                            yield f"data: {json.dumps({'text': content})}\n\n"
                    except Exception:
                        pass
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'text': f'⚠️ OpenRouter Fallback failed: {str(e)}. Running local offline analysis.'})}\n\n"
            # final fallback to local rule-based summary
            yield from self._stream_fallback([], prompt)

    def _stream_fallback(self, flows: List[dict], query: str = None) -> Generator[str, None, None]:
        """Provides a detailed mock streaming response when API key is missing."""
        intro = "### 💻 Offline Traffic Insights (API Key Missing)\n\n"
        if not self.api_key:
            intro += "> [!WARNING]\n"
            intro += "> **Gemini API Key not set.** Please enter your Gemini API Key in the sidebar to unlock the full interactive chat assistant! Running local static analysis in the meantime.\n\n"
            
        # Count stats
        threats = []
        protocols = {}
        total_bytes = 0
        
        for f in flows:
            total_bytes += f["byte_count"]
            protocols[f["protocol"]] = protocols.get(f["protocol"], 0) + 1
            if f.get("anomalies"):
                threats.extend(f["anomalies"])
                
        explanation = f"""Here is a breakdown of your packet capture:

1. **Traffic Summary**:
   - We analyzed **{len(flows)} network connections** (flows).
   - Total volume of traffic: **{total_bytes / 1024:.2f} KB** ({total_bytes} bytes).
   - Protocol split: {", ".join([f"**{k}** ({v} flows)" for k, v in protocols.items()])}.

2. **Security & Anomalies**:
   {f'🚨 **{len(threats)} Warning(s) Detected**: ' + ', '.join(set(threats)) if threats else '✅ **No security anomalies detected.** All flows match regular patterns.'}

3. **Plain-English Explanation**:
   - **What is a flow?** A flow represents a complete conversation between two computers. For example, when your computer requests a website, a flow is opened.
   - **What is DNS?** It's like the phonebook of the internet. It translates domain names (like `google.com`) into computer-readable numbers (IP addresses).
   - **What is TLS/HTTPS?** This is secure, encrypted web browsing. Even though we can't see the password or website contents, our engine extracted the Server Name Indication (SNI) to identify that you accessed domains like {', '.join(set([f['domain'] for f in flows if f['domain']][:3])) or 'web services'}.

To filter or block any of this traffic in the C++ DPI engine, you can generate rules like:
- **`--block-app YouTube`** to drop streaming packets.
- **`--block-ip 192.168.1.222`** to block suspicious machines.
"""
        # Stream it word by word to simulate streaming
        full_text = intro + explanation
        words = full_text.split(" ")
        chunk_size = 5
        
        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i+chunk_size]) + " "
            yield f"data: {json.dumps({'text': chunk})}\n\n"
            time.sleep(0.05)
            
        yield "data: [DONE]\n\n"
