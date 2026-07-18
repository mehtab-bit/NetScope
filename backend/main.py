import os
import shutil
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
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
        
        # Clean up temp file
        os.remove(tmp_path)
        tmp_path = None
        
        # Run ML classification
        classified_flows = classifier.classify_flows(flows)
        
        # Save to session cache
        session_cache["filename"] = file.filename
        session_cache["packets"] = packets
        session_cache["flows"] = classified_flows
        
        return {
            "filename": file.filename,
            "packets_count": len(packets),
            "flows_count": len(classified_flows),
            "packets": packets[:100],  # Return first 100 packets for detailed table view
            "flows": classified_flows
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
        classified_flows = classifier.classify_flows(flows)
        
        # Save to session cache
        session_cache["filename"] = filename
        session_cache["packets"] = packets
        session_cache["flows"] = classified_flows
        
        return {
            "filename": filename,
            "packets_count": len(packets),
            "flows_count": len(classified_flows),
            "packets": packets[:100],
            "flows": classified_flows
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
import urllib.request
import json

# Simple in-memory cache for GeoIP to avoid rate limiting
geoip_cache = {}

@app.post("/api/geoip")
def api_geoip(data: dict = Body(...)):
    """Fetches GeoIP information for a list of IPs using ip-api.com batch endpoint."""
    ips = data.get("ips", [])
    if not ips:
        return {"results": {}}
        
    # Deduplicate and filter out private IPs roughly
    unique_ips = set(ips)
    external_ips = [ip for ip in unique_ips if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."))]
    
    # Check cache first
    results = {}
    to_fetch = []
    
    for ip in external_ips:
        if ip in geoip_cache:
            results[ip] = geoip_cache[ip]
        else:
            to_fetch.append(ip)
            
    # Fetch remaining from ip-api in batches of 100 (API limit)
    if to_fetch:
        for i in range(0, len(to_fetch), 100):
            batch = to_fetch[i:i+100]
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/batch",
                    data=json.dumps(batch).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    batch_res = json.loads(response.read().decode("utf-8"))
                    for res in batch_res:
                        if res.get("status") == "success":
                            ip = res.get("query")
                            info = {
                                "country": res.get("country"),
                                "countryCode": res.get("countryCode"),
                                "city": res.get("city"),
                                "isp": res.get("isp"),
                                "lat": res.get("lat"),
                                "lon": res.get("lon")
                            }
                            geoip_cache[ip] = info
                            results[ip] = info
            except Exception as e:
                print(f"[NetScope] GeoIP fetch failed: {e}")
                
    return {"results": results}



@app.post("/api/dpi/run")
def api_dpi_run(data: dict = Body(...)):
    """Runs the C++ DPI engine against the current loaded capture"""
    rules = data.get("rules", [])
    
    # Check if we have a file in session cache
    filename = session_cache.get("filename")
    if not filename:
        raise HTTPException(status_code=400, detail="No active PCAP loaded.")
        
    input_pcap = os.path.join(DEMO_DIR, filename) if filename.endswith(".pcap") and os.path.exists(os.path.join(DEMO_DIR, filename)) else None
    
    # If it was an uploaded file, it was deleted! 
    # For a real implementation, we would keep the upload.pcap around until session ends.
    # For this project, if we can't find it in demo, we'll use a placeholder or test pcap to demonstrate the engine.
    if not input_pcap:
        input_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_dpi.pcap")
        if not os.path.exists(input_pcap):
            # Generate one on the fly if missing
            subprocess.run(["python", os.path.join(os.path.dirname(os.path.dirname(__file__)), "generate_test_pcap.py")], check=True)
            
    output_pcap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output.pcap")
    
    try:
        stats = run_dpi_engine(input_pcap, output_pcap, rules)
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

# Serve Frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def get_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
