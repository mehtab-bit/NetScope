import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import List, Dict, Tuple

class TrafficClassifier:
    """
    Combines rule-based classification, statistical machine learning,
    and heuristic anomaly detection to label network flows.
    """
    
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
        self._train_local_model()
        
    def _train_local_model(self):
        """
        Trains a local Random Forest classifier on synthetic packet flow profiles
        to distinguish application categories when domain/SNI metadata is absent.
        """
        # Features: [dst_port, packet_count, byte_count, duration, mean_packet_size]
        # Labels: 0=Web/Browsing, 1=Video Streaming, 2=File Transfer/P2P, 3=Chat/Interactive
        
        data = []
        labels = []
        
        # 1. Web/Browsing: moderate packets, small-medium sizes, bursty duration
        for _ in range(50):
            data.append([
                random_port([80, 443, 8080]),
                np.random.randint(5, 30),
                np.random.randint(1000, 20000),
                np.random.uniform(0.5, 10.0),
                np.random.uniform(100, 800)
            ])
            labels.append(0)
            
        # 2. Video Streaming: high packets, high bytes, long duration, large packet sizes
        for _ in range(50):
            data.append([
                443,
                np.random.randint(50, 500),
                np.random.randint(50000, 1000000),
                np.random.uniform(10.0, 60.0),
                np.random.uniform(1000, 1450)
            ])
            labels.append(1)
            
        # 3. File Transfer / Upload: high bytes, large sizes, moderate packets
        for _ in range(50):
            data.append([
                random_port([21, 22, 443]),
                np.random.randint(20, 200),
                np.random.randint(20000, 500000),
                np.random.uniform(2.0, 30.0),
                np.random.uniform(900, 1400)
            ])
            labels.append(2)
            
        # 4. Chat/Interactive/DNS: small packets, very small bytes, fast duration, small size
        for _ in range(50):
            data.append([
                random_port([53, 443, 5222]),
                np.random.randint(2, 10),
                np.random.randint(100, 1500),
                np.random.uniform(0.1, 2.0),
                np.random.uniform(50, 150)
            ])
            labels.append(3)
            
        X = np.array(data)
        y = np.array(labels)
        
        self.model.fit(X, y)
        self.is_trained = True
        
    def classify_flows(self, flows: List[dict]) -> List[dict]:
        """
        Classifies a list of flows, adding ML labels and detecting anomalies.
        """
        classified_flows = []
        
        # Anomaly Detection tracking
        port_scan_track = {}  # (src_ip, dst_ip) -> set(dst_ports)
        
        # Pass 1: Gather info for port-scan detection
        for flow in flows:
            src_ip = flow["src_ip"]
            dst_ip = flow["dst_ip"]
            dst_port = flow["dst_port"]
            
            # Simple heuristic: scan tracking
            if flow["protocol"] == "TCP" or flow["protocol"] == "UDP":
                key = (src_ip, dst_ip)
                if key not in port_scan_track:
                    port_scan_track[key] = set()
                port_scan_track[key].add(dst_port)
                
        # Pass 2: Classify and flag
        for flow in flows:
            flow_copy = flow.copy()
            src_ip = flow_copy["src_ip"]
            dst_ip = flow_copy["dst_ip"]
            dst_port = flow_copy["dst_port"]
            pkt_count = flow_copy["packet_count"]
            byte_count = flow_copy["byte_count"]
            duration = flow_copy["duration"]
            mean_size = flow_copy["mean_packet_size"]
            domain = flow_copy["domain"]
            
            # 1. Rule-based Label check first
            category = "UNKNOWN"
            if flow_copy["app_category"] != "UNKNOWN":
                category = flow_copy["app_category"]
            elif dst_port == 53 or flow_copy["protocol"] == "DNS":
                category = "DNS"
            elif dst_port == 80:
                category = "HTTP Web"
            elif dst_port == 22:
                category = "SSH Secure Login"
            elif dst_port == 21:
                category = "FTP File Transfer"
            
            # 2. If category is still Web/UNKNOWN, apply ML classification
            confidence = 1.0
            if category in ("UNKNOWN", "HTTPS/Web"):
                # Features: [dst_port, packet_count, byte_count, duration, mean_packet_size]
                feat = np.array([[dst_port, pkt_count, byte_count, duration, mean_size]])
                try:
                    pred_class = self.model.predict(feat)[0]
                    prob_array = self.model.predict_proba(feat)[0]
                    confidence = float(max(prob_array))
                    
                    ml_categories = {
                        0: "Web Browsing",
                        1: "Streaming Media",
                        2: "File Transfer",
                        3: "Chat/Interactive"
                    }
                    category = ml_categories.get(pred_class, "HTTPS/Web")
                except Exception:
                    category = "HTTPS/Web"
                    confidence = 0.5
            
            flow_copy["app_category"] = category
            flow_copy["ml_confidence"] = confidence
            
            # 3. Anomaly Detection
            anomalies = []
            
            # Check Port Scan
            scan_key = (src_ip, dst_ip)
            unique_ports = port_scan_track.get(scan_key, set())
            if len(unique_ports) >= 10:
                anomalies.append("Port Scan Threat (Multiple connections to unique ports)")
                flow_copy["app_category"] = "SECURITY THREAT (Port Scan)"
                
            # Check Heavy Upload / Exfiltration
            # Standard web traffic is download-heavy. If we see large upload bytes, flag it.
            # (Note: In a real flow, we would split sent vs received bytes.
            # Here, we use total byte count and packet count as an proxy indicator)
            if byte_count > 500000 and mean_size > 1200 and pkt_count < 100:
                anomalies.append("Suspicious High-Volume File Transfer")
                
            flow_copy["anomalies"] = anomalies
            flow_copy["is_secure"] = (dst_port == 443 or dst_port == 22)
            
            classified_flows.append(flow_copy)
            
        return classified_flows

def random_port(ports: List[int]) -> int:
    return np.random.choice(ports)
