import os
import shutil
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from typing import List, Dict, Optional

from backend.pcap_parser import PcapParser
from backend.traffic_classifier import TrafficClassifier
from backend.gemini_streamer import GeminiStreamer

# Dynamic .env configuration loader for secure key management
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(root_dir, ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

app = FastAPI(title="AI Packet Analyzer API", version="1.0")

# Session cache for detailed flow inspection
session_cache = {
    "filename": None,
    "pcap_path": None,
    "packets": [],
    "flows": []
}

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Classifier
classifier = TrafficClassifier()

# Helper to find demo files path
DEMO_DIR = os.path.join(os.path.dirname(__file__), "demo_pcaps")

@app.get("/api/health")
def health_check():
    """Simple health check endpoint for deployment monitoring."""
    return {"status": "healthy", "service": "NetScope API"}

@app.get("/api/demos")
def get_demos():
    """Returns list of preloaded demo PCAP files for beginners."""
    return [
        {
            "id": "safe_browsing",
            "name": "🌐 Safe Web Browsing Session",
            "description": "A capture representing normal internet usage: looking up domains via DNS, searching Google, and loading a page from GitHub.",
            "file": "safe_browsing.pcap"
        },
        {
            "id": "video_stream",
            "name": "🎬 Video Streaming Session",
            "description": "Simulates heavy bandwidth consumption. Watch how the flow data displays high packet counts and large payload sizes targeting YouTube servers.",
            "file": "video_stream.pcap"
        },
        {
            "id": "port_scan",
            "name": "🚨 Suspicious Port Scan Attack",
            "description": "A simulation of a local attack where an unknown IP scans multiple ports on a router. Perfect for seeing the AI flag security anomalies.",
            "file": "port_scan.pcap"
        }
    ]

@app.post("/api/config/key")
def configure_key(response: Response, data: dict = Body(...)):
    """Saves the Gemini API Key into an HTTP-Only cookie for XSS prevention."""
    api_key = data.get("api_key", "").strip()
    if not api_key:
        response.delete_cookie("gemini_api_key")
        return {"status": "cleared"}
    
    response.set_cookie(
        key="gemini_api_key",
        value=api_key,
        httponly=True,
        samesite="lax",
        max_age=3600*24*7 # 7 days
    )
    return {"status": "configured"}

@app.get("/api/config/status")
def get_config_status(request: Request):
    """Checks if the Gemini API key is configured on the server or cookie."""
    cookie_key = request.cookies.get("gemini_api_key")
    env_key = os.environ.get("GEMINI_API_KEY")
    return {"configured": bool(cookie_key or env_key)}

@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads a PCAP file, parses it, and classifies the traffic flows."""
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are supported.")
        
    # Save upload file to temporary location
    tmp_path = None
    try:
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
            
        # Parse & classify
        parser = PcapParser(tmp_path)
        packets, flows = parser.parse()
        
        # Run DPI Engine over the upload
        output_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.pcap")
        stats = run_dpi_engine(tmp_path, output_pcap, [])
        
        from backend.database import get_db
        db = get_db()
        db.save_session(os.path.basename(file.filename), stats)
        
        # Save to persistent upload location for DPI run and packet inspection
        active_pcap_path = os.path.join(root_dir, "active_upload.pcap")
        shutil.copy(tmp_path, active_pcap_path)
        
        session_cache["filename"] = file.filename
        session_cache["pcap_path"] = active_pcap_path
        session_cache["packets"] = packets
        session_cache["flows"] = flows
        
        # Clean up temp file
        os.remove(tmp_path)
        tmp_path = None
        
        return {
            "filename": file.filename,
            "packets_count": stats.get("total_packets", len(packets)),
            "flows_count": stats.get("active_flows", len(flows)),
            "packets": packets[:100],  # Return first 100 packets for detailed table view
            "flows": flows,
            "dpi_stats": stats
        }
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {str(e)}")

@app.post("/api/analyze-demo/{demo_id}")
def analyze_demo(demo_id: str):
    """Analyzes a preloaded demo PCAP file."""
    demos = {
        "safe_browsing": "safe_browsing.pcap",
        "video_stream": "video_stream.pcap",
        "port_scan": "port_scan.pcap"
    }
    
    filename = demos.get(demo_id)
    if not filename:
        raise HTTPException(status_code=404, detail="Demo capture not found.")
        
    filepath = os.path.join(DEMO_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=500, detail=f"Demo file '{filename}' missing on server.")
        
    try:
        parser = PcapParser(filepath)
        packets, flows = parser.parse()
        
        # Run DPI Engine over the demo
        output_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.pcap")
        stats = run_dpi_engine(filepath, output_pcap, [])
        
        from backend.database import get_db
        db = get_db()
        db.save_session(os.path.basename(filepath), stats)
        
        # Save to session cache for DPI run and packet inspection
        session_cache["filename"] = filename
        session_cache["pcap_path"] = filepath
        session_cache["packets"] = packets
        session_cache["flows"] = flows
        
        # Merge C++ DPI stats with Python parsed packets for the UI
        return {
            "filename": filename,
            "packets_count": stats.get("total_packets", len(packets)),
            "flows_count": stats.get("active_flows", len(flows)),
            "packets": packets[:100],
            "flows": flows, # fallback for UI packet drill down
            "dpi_stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze demo capture: {str(e)}")

@app.get("/api/flow-packets/{flow_id}")
def get_flow_packets(flow_id: int):
    """Returns packets belonging to a specific flow for the inspection drawer."""
    target_flow = None
    for f in session_cache["flows"]:
        if f["flow_id"] == flow_id:
            target_flow = f
            break
            
    if not target_flow:
        raise HTTPException(status_code=404, detail="Flow conversation not found.")
        
    src_ip = target_flow["src_ip"]
    dst_ip = target_flow["dst_ip"]
    src_port = target_flow["src_port"]
    dst_port = target_flow["dst_port"]
    protocol = target_flow["protocol"]
    
    flow_packets = []
    for p in session_cache["packets"]:
        match_forward = (
            p["src_ip"] == src_ip and p["dst_ip"] == dst_ip and
            p["src_port"] == src_port and p["dst_port"] == dst_port and
            p["protocol"] == protocol
        )
        match_reverse = (
            p["dst_ip"] == src_ip and p["src_ip"] == dst_ip and
            p["dst_port"] == src_port and p["src_port"] == dst_port and
            p["protocol"] == protocol
        )
        if match_forward or match_reverse:
            flow_packets.append(p)
            
    return {
        "flow_id": flow_id,
        "packets": flow_packets[:50]  # Cap at 50 packets for UI performance
    }

@app.post("/api/chat")
def chat_explain(
    request: Request,
    flows: List[dict] = Body(..., embed=True),
    user_query: Optional[str] = Body(None, embed=True),
    chat_history: Optional[List[dict]] = Body(None, embed=True),
    api_key: Optional[str] = Body(None, embed=True)
):
    """
    Streams a conversational Gemini explanation of the packet flows.
    """
    # Key precedence: 1. HTTP-Only Cookie, 2. Env Var, 3. Body Param
    cookie_key = request.cookies.get("gemini_api_key")
    resolved_key = cookie_key or os.environ.get("GEMINI_API_KEY") or api_key
    
    streamer = GeminiStreamer(api_key=resolved_key)
    
    return StreamingResponse(
        streamer.stream_analysis(flows, user_query, chat_history),
        media_type="text/event-stream"
    )

from backend.dpi_runner import run_dpi_engine
from backend.geoip_lookup import get_geoip

@app.post("/api/geoip")
def api_geoip(data: dict = Body(...)):
    """Fetches GeoIP information for a list of IPs using offline GeoLite2 database."""
    ips = data.get("ips", [])
    if not ips:
        return {"results": {}}
        
    unique_ips = set(ips)
    external_ips = [ip for ip in unique_ips if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."))]
    
    results = {}
    geo = get_geoip()
    
    for ip in external_ips:
        res = geo.lookup_ip(ip)
        if res["country"] != "Unknown":
            results[ip] = res
            
    return {"results": results}



@app.post("/api/dpi/run")
def api_dpi_run(data: dict = Body(...)):
    """Runs the C++ DPI engine against the current loaded capture"""
    rules = data.get("rules", [])
    
    pcap_path = session_cache.get("pcap_path")
    if not pcap_path or not os.path.exists(pcap_path):
        raise HTTPException(status_code=400, detail="No active PCAP loaded.")
        
    output_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.pcap")
    
    try:
        stats = run_dpi_engine(pcap_path, output_pcap, rules)
        
        # Save to SQLite
        from backend.database import get_db
        db = get_db()
        db.save_session(os.path.basename(pcap_path), stats)
        
        # Parse the filtered output.pcap to get new packets and flows
        parser = PcapParser(output_pcap)
        filtered_packets, filtered_flows = parser.parse()
        
        # Update session cache with the filtered pcap path and details
        session_cache["filename"] = "filtered_" + os.path.basename(pcap_path)
        session_cache["pcap_path"] = output_pcap
        session_cache["packets"] = filtered_packets
        session_cache["flows"] = filtered_flows
        
        stats["packets"] = filtered_packets[:100]
        stats["flows"] = filtered_flows
        stats["filename"] = "filtered_" + os.path.basename(pcap_path)
        stats["packets_count"] = stats.get("forwarded", len(filtered_packets))
        stats["flows_count"] = len(filtered_flows)
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dpi/download")
def api_dpi_download():
    """Downloads the generated filtered output PCAP"""
    output_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.pcap")
    if not os.path.exists(output_pcap):
        raise HTTPException(status_code=404, detail="No filtered PCAP available. Run the engine first.")
        
    return FileResponse(
        output_pcap, 
        media_type="application/vnd.tcpdump.pcap",
        filename="filtered_output.pcap"
    )

@app.get("/api/history")
def api_history():
    """Returns past DPI engine executions from SQLite."""
    from backend.database import get_db
    db = get_db()
    return {"history": db.get_history()}

@app.get("/api/reports/csv")
def export_csv_report():
    """Generates a CSV report of the session history."""
    from backend.database import get_db
    import io
    import csv
    
    db = get_db()
    history = db.get_history()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Filename", "Total Packets", "Total Flows", "Malicious Flows"])
    
    for row in history:
        writer.writerow([
            row["id"], row["timestamp"], row["filename"], 
            row["total_packets"], row["total_flows"], row["malicious_flows"]
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=session_report.csv"}
    )

@app.post("/api/save-explanation")
def api_save_explanation(body: dict = Body(...)):
    """Saves the completed AI analysis text into the session cache."""
    session_cache["ai_explanation"] = body.get("explanation")
    return {"status": "success"}

@app.get("/api/export-report", response_class=HTMLResponse)
def api_export_report():
    """Generates a beautifully styled, print-ready HTML incident report of the session."""
    filename = session_cache.get("filename") or "No capture loaded"
    flows = session_cache.get("flows") or []
    packets = session_cache.get("packets") or []
    ai_raw = session_cache.get("ai_explanation") or "AI Analysis has not been run or is loading. Run analysis to populate this section."
    
    from datetime import datetime
    import re
    import json
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate metadata
    total_bytes = sum(f.get("byte_count", 0) for f in flows)
    volume_mb = total_bytes / (1024 * 1024)
    packets_count = len(packets) if packets else sum(f.get("packet_count", 0) for f in flows)
    
    anomalies_count = 0
    for f in flows:
        anomalies_count += len(f.get("anomalies") or [])
        
    # Markdown helper
    def md_to_html(md: str) -> str:
        if not md:
            return ""
        # Escape HTML tags to prevent injections, but keep basic formatting
        h = md.replace("<", "&lt;").replace(">", "&gt;")
        # Headers
        h = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', h, flags=re.MULTILINE)
        h = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', h, flags=re.MULTILINE)
        h = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', h, flags=re.MULTILINE)
        # Bold
        h = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', h)
        # Blockquotes
        h = re.sub(r'^>\s+(.*?)$', r'<blockquote>\1</blockquote>', h, flags=re.MULTILINE)
        # Lists
        h = re.sub(r'^\s*-\s+(.*?)$', r'<li>\1</li>', h, flags=re.MULTILINE)
        # Code
        h = re.sub(r'`(.*?)`', r'<code>\1</code>', h)
        # Linebreaks
        h = h.replace("\n", "<br>")
        return h
        
    ai_summary_html = md_to_html(ai_raw)
    
    # Anomalies
    if anomalies_count > 0:
        anomalies_html = '<div class="section-title">🚨 Flagged Threat Alerts</div><div class="report-block" style="border-left: 4px solid var(--red); background: var(--red-light);"><ul>'
        for f in flows:
            if f.get("anomalies"):
                anoms = ", ".join(f["anomalies"])
                anomalies_html += f'<li><strong>Flow #{f["flow_id"]}</strong> ({f["src_ip"]}:{f["src_port"]} &rarr; {f["dst_ip"]}:{f["dst_port"]}): <span style="color: var(--red); font-weight: 600;">{anoms}</span></li>'
        anomalies_html += '</ul></div>'
    else:
        anomalies_html = '<div class="section-title">Security Alert Assessment</div><div class="report-block" style="border-left: 4px solid var(--green); background: var(--green-light);"><p style="color: var(--green); font-weight: 600;">✅ No malicious behavior or traffic anomalies detected. The parsed flows do not contain uniform beacons, known threat intelligence feed hits, or suspicious port configurations.</p></div>'
        
    # Protocol distribution
    proto_stats = {}
    total_bytes_all = total_bytes or 1
    for f in flows:
        proto = f.get("protocol", "Unknown")
        if proto not in proto_stats:
            proto_stats[proto] = {"flows": 0, "packets": 0, "bytes": 0}
        proto_stats[proto]["flows"] += 1
        proto_stats[proto]["packets"] += f.get("packet_count", 0)
        proto_stats[proto]["bytes"] += f.get("byte_count", 0)
        
    proto_rows = ""
    for proto, stat in proto_stats.items():
        share = (stat["bytes"] / total_bytes_all) * 100
        proto_rows += f"""
        <tr>
            <td><strong>{proto}</strong></td>
            <td>{stat["flows"]}</td>
            <td>{stat["packets"]:,}</td>
            <td>{(stat["bytes"]/1024):.1f} KB</td>
            <td>{share:.1f}%</td>
        </tr>
        """
        
    # Flow conversations (top 30 by bytes)
    sorted_flows = sorted(flows, key=lambda x: x.get("byte_count", 0), reverse=True)[:30]
    flow_rows = ""
    for f in sorted_flows:
        sev_badge = '<span class="badge normal">Normal</span>'
        if f.get("anomalies"):
            sev_badge = '<span class="badge high">Alert</span>'
        domain_or_sni = f.get("domain") or "-"
        flow_rows += f"""
        <tr>
            <td>#{f["flow_id"]}</td>
            <td><code>{f["src_ip"]}:{f["src_port"]}</code></td>
            <td><code>{f["dst_ip"]}:{f["dst_port"]}</code></td>
            <td>{f["protocol"]}</td>
            <td>{f["dst_port"]}</td>
            <td>{f["app_category"]}</td>
            <td style="max-width: 150px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="{domain_or_sni}">{domain_or_sni}</td>
            <td>{f["packet_count"]:,}</td>
            <td>{(f["byte_count"]/1024):.1f} KB</td>
            <td>{sev_badge}</td>
        </tr>
        """
        
    serialized_packets = json.dumps(packets[:1500])
    serialized_flows = json.dumps(flows)
        
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>NetScope Incident Report - {filename}</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            :root {{
                --primary: #0f172a;
                --text: #334155;
                --text-light: #64748b;
                --border: #e2e8f0;
                --accent: #0284c7;
                --bg-light: #f8fafc;
                --red: #dc2626;
                --red-light: #fef2f2;
                --green: #16a34a;
                --green-light: #f0fdf4;
            }}
            * {{
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }}
            body {{
                font-family: 'Outfit', sans-serif;
                color: var(--text);
                line-height: 1.6;
                background: #fff;
                padding: 40px;
            }}
            .report-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 2px solid var(--primary);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            .report-title h1 {{
                font-size: 24px;
                color: var(--primary);
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .report-title span {{
                font-size: 13px;
                color: var(--text-light);
            }}
            .logo {{
                font-size: 20px;
                font-weight: 800;
                color: var(--accent);
            }}
            .logo i {{
                margin-right: 6px;
            }}
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-bottom: 30px;
            }}
            .summary-card {{
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 16px;
                background: var(--bg-light);
                text-align: center;
            }}
            .summary-card .value {{
                font-size: 16px;
                font-weight: 700;
                color: var(--primary);
                word-break: break-all;
            }}
            .summary-card .label {{
                font-size: 11px;
                text-transform: uppercase;
                color: var(--text-light);
                margin-top: 4px;
                font-weight: 500;
            }}
            .summary-card.alert {{
                background: var(--red-light);
                border-color: rgba(220, 38, 38, 0.2);
            }}
            .summary-card.alert .value {{
                color: var(--red);
            }}
            .section-title {{
                font-size: 16px;
                font-weight: 700;
                color: var(--primary);
                border-bottom: 1px solid var(--border);
                padding-bottom: 8px;
                margin-bottom: 16px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-top: 30px;
                page-break-after: avoid;
            }}
            .report-block {{
                background: var(--bg-light);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 24px;
                font-size: 13px;
            }}
            .report-block h3 {{
                font-size: 14px;
                color: var(--primary);
                margin-top: 12px;
                margin-bottom: 6px;
            }}
            .report-block blockquote {{
                border-left: 3px solid var(--accent);
                background: #f0f9ff;
                padding: 10px 14px;
                margin: 12px 0;
                font-style: italic;
            }}
            .report-block code {{
                font-family: monospace;
                background: #e2e8f0;
                padding: 2px 4px;
                border-radius: 3px;
                font-size: 12px;
            }}
            .report-block li {{
                margin-left: 20px;
                margin-bottom: 4px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 12px;
                margin-bottom: 30px;
                page-break-inside: auto;
            }}
            tr {{
                page-break-inside: avoid;
                page-break-after: auto;
            }}
            th, td {{
                padding: 10px 12px;
                text-align: left;
                border-bottom: 1px solid var(--border);
            }}
            th {{
                background: var(--bg-light);
                font-weight: 600;
                color: var(--primary);
                text-transform: uppercase;
                font-size: 10px;
                letter-spacing: 0.5px;
            }}
            .badge {{
                display: inline-block;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .badge.high {{
                background: var(--red-light);
                color: var(--red);
                border: 1px solid rgba(220, 38, 38, 0.2);
            }}
            .badge.normal {{
                background: var(--green-light);
                color: var(--green);
                border: 1px solid rgba(22, 163, 74, 0.2);
            }}
            .print-btn {{
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: var(--accent);
                color: #fff;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                z-index: 999;
            }}
            .charts-grid {{
                display: grid;
                grid-template-columns: 1.2fr 1fr;
                gap: 16px;
                margin-bottom: 30px;
                page-break-inside: avoid;
            }}
            .chart-box {{
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 16px;
                background: var(--bg-light);
                min-height: 230px;
            }}
            .chart-box h4 {{
                font-size: 11px;
                text-transform: uppercase;
                color: var(--text-light);
                margin-bottom: 12px;
                letter-spacing: 0.5px;
            }}
            @media print {{
                .print-btn {{
                    display: none;
                }}
                body {{
                    padding: 0;
                }}
                .summary-card {{
                    background: #fff !important;
                    -webkit-print-color-adjust: exact;
                    print-color-adjust: exact;
                }}
                .report-block {{
                    background: #fff !important;
                    -webkit-print-color-adjust: exact;
                    print-color-adjust: exact;
                }}
                .chart-box {{
                    background: #fff !important;
                    -webkit-print-color-adjust: exact;
                    print-color-adjust: exact;
                }}
            }}
        </style>
    </head>
    <body>
        <button class="print-btn" onclick="window.print()">Print / Save PDF</button>

        <header class="report-header">
            <div class="report-title">
                <h1>NetScope Security Analysis Report</h1>
                <span>Generated on {date_str} &bull; Target: {filename}</span>
            </div>
            <div class="logo">
                NetScope
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{filename}</div>
                <div class="label">Target PCAP</div>
            </div>
            <div class="summary-card">
                <div class="value">{volume_mb:.2f} MB</div>
                <div class="label">Total Volume</div>
            </div>
            <div class="summary-card">
                <div class="value">{packets_count:,}</div>
                <div class="label">Packets</div>
            </div>
            <div class="summary-card alert">
                <div class="value">{anomalies_count}</div>
                <div class="label">Threat Warnings</div>
            </div>
        </div>

        <div class="section-title">Executive Traffic Summary</div>
        <div class="report-block">
            {ai_summary_html}
        </div>

        {anomalies_html}

        <div class="section-title">Visual Telemetry</div>
        <div class="charts-grid">
            <div class="chart-box">
                <h4>Bandwidth Timeline (Bytes/Sec)</h4>
                <div style="width: 100%; height: 170px;">
                    <canvas id="reportBandwidthChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h4>Active Network Topology Graph</h4>
                <div style="width: 100%; height: 170px; background: #ffffff; border: 1px solid var(--border); border-radius: 4px;">
                    <canvas id="reportTopologyCanvas"></canvas>
                </div>
            </div>
        </div>

        <div class="section-title">Protocol Distribution</div>
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Flow Count</th>
                    <th>Packet Count</th>
                    <th>Byte Count</th>
                    <th>Volume Share</th>
                </tr>
            </thead>
            <tbody>
                {proto_rows}
            </tbody>
        </table>


        <script>
            const packetsData = {serialized_packets};
            const flowsData = {serialized_flows};

            // 1. Draw Bandwidth Chart
            const timeMap = {{}};
            let minTime = Infinity;
            let maxTime = -Infinity;
            packetsData.forEach(p => {{
                const sec = Math.floor(p.timestamp);
                if (sec < minTime) minTime = sec;
                if (sec > maxTime) maxTime = sec;
                timeMap[sec] = (timeMap[sec] || 0) + p.length;
            }});

            const labels = [];
            const dataPoints = [];
            if (minTime !== Infinity && maxTime !== -Infinity) {{
                for (let t = minTime; t <= maxTime; t++) {{
                    labels.push((t - minTime) + "s");
                    dataPoints.push(timeMap[t] || 0);
                }}
            }}

            new Chart(document.getElementById('reportBandwidthChart'), {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Traffic Rate',
                        data: dataPoints,
                        borderColor: '#0284c7',
                        backgroundColor: 'rgba(2, 132, 199, 0.05)',
                        borderWidth: 2,
                        pointRadius: 1,
                        fill: true,
                        tension: 0.3
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        x: {{ grid: {{ display: false }}, ticks: {{ font: {{ family: 'Outfit', size: 9 }} }} }},
                        y: {{ ticks: {{ font: {{ family: 'Outfit', size: 9 }} }} }}
                    }}
                }}
            }});

            // 2. Draw Static Network Topology
            const canvas = document.getElementById('reportTopologyCanvas');
            const ctx = canvas.getContext('2d');
            
            const rect = canvas.parentNode.getBoundingClientRect();
            const width = canvas.width = rect.width || 300;
            const height = canvas.height = 170;

            const centerNode = {{
                id: "local_host",
                label: "Local Client",
                x: width / 2,
                y: height / 2,
                size: 11,
                color: "#0284c7"
            }};

            const externalIPMap = {{}};
            flowsData.forEach(flow => {{
                const extIP = flow.dst_ip === "192.168.1.100" ? flow.src_ip : flow.dst_ip;
                if (extIP !== "192.168.1.100") {{
                    externalIPMap[extIP] = flow;
                }}
            }});

            const externalIPs = Object.values(externalIPMap).slice(0, 6);
            const maxBytes = Math.max(...externalIPs.map(f => f.byte_count), 1);

            const nodes = [centerNode];
            const links = [];

            externalIPs.forEach((flow, index) => {{
                const angle = (index / externalIPs.length) * Math.PI * 2;
                const radius = Math.min(width, height) * 0.33;
                const x = width / 2 + Math.cos(angle) * radius;
                const y = height / 2 + Math.sin(angle) * radius;

                let color = "#3b82f6";
                if (flow.anomalies && flow.anomalies.length > 0) {{
                    color = "#ef4444";
                }} else if (flow.protocol === "DNS") {{
                    color = "#8b5cf6";
                }}

                const label = flow.app_category !== "UNKNOWN" ? flow.app_category : flow.domain || flow.dst_ip;
                const size = 5 + (flow.byte_count / maxBytes) * 7;

                const node = {{
                    id: "node_" + index,
                    label: label,
                    x: x,
                    y: y,
                    size: size,
                    color: color
                }};
                nodes.push(node);
                links.push({{ source: centerNode, target: node }});
            }});

            // Render static frame
            ctx.clearRect(0, 0, width, height);

            // Draw Links
            links.forEach(l => {{
                ctx.beginPath();
                ctx.moveTo(l.source.x, l.source.y);
                ctx.lineTo(l.target.x, l.target.y);
                ctx.strokeStyle = "rgba(0, 0, 0, 0.08)";
                ctx.lineWidth = 1;
                ctx.stroke();
            }});

            // Draw Nodes
            nodes.forEach(n => {{
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2);
                ctx.fillStyle = n.color;
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = "rgba(0, 0, 0, 0.1)";
                ctx.stroke();

                ctx.font = "9px Outfit, sans-serif";
                ctx.fillStyle = "#475569";
                ctx.textAlign = "center";
                ctx.fillText(n.label, n.x, n.y + n.size + 10);
            }});

            // Auto-open print dialog when loaded
            window.addEventListener('load', () => {{
                setTimeout(() => {{ window.print(); }}, 800);
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# Serve Frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def get_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
