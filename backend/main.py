import os
import shutil
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
from typing import List, Dict, Optional

from backend.pcap_parser import PcapParser
from backend.traffic_classifier import TrafficClassifier
from backend.gemini_streamer import GeminiStreamer

app = FastAPI(title="AI Packet Analyzer API", version="1.0")

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
        
        return {
            "filename": filename,
            "packets_count": len(packets),
            "flows_count": len(classified_flows),
            "packets": packets[:100],
            "flows": classified_flows
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze demo capture: {str(e)}")

@app.post("/api/chat")
def chat_explain(
    flows: List[dict] = Body(..., embed=True),
    user_query: Optional[str] = Body(None, embed=True),
    chat_history: Optional[List[dict]] = Body(None, embed=True),
    api_key: Optional[str] = Body(None, embed=True)
):
    """
    Streams a conversational Gemini explanation of the packet flows.
    """
    streamer = GeminiStreamer(api_key=api_key)
    
    return StreamingResponse(
        streamer.stream_analysis(flows, user_query, chat_history),
        media_type="text/event-stream"
    )

# Serve Frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def get_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
