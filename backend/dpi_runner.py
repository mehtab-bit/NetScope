import subprocess
import os
import sys
import json
import logging
from typing import Dict, Any, List
from backend.threat_intel import get_threat_intel
from backend.geoip_lookup import get_geoip

logger = logging.getLogger(__name__)

# Determine correct binary name based on OS
if sys.platform == "win32":
    DPI_ENGINE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dpi_engine.exe")
else:
    DPI_ENGINE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dpi_engine")

def run_dpi_engine(input_pcap: str, output_pcap: str, rules: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Executes the C++ DPI engine as a subprocess with the given rules.
    """
    if not os.path.exists(DPI_ENGINE_PATH):
        raise FileNotFoundError(f"DPI Engine binary not found at {DPI_ENGINE_PATH}. Please compile it first.")

    # Write rules to rules.txt
    rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules.txt")
    with open(rules_path, "w", encoding="utf-8") as f:
        for rule in rules:
            rule_type = rule.get("type")
            rule_val = rule.get("value")
            
            if rule_type in ("IP", "--block-ip"):
                f.write(f"BLOCK_IP {rule_val}\n")
            elif rule_type in ("App", "--block-app"):
                f.write(f"BLOCK_APP {rule_val}\n")
            elif rule_type in ("Domain", "--block-domain"):
                f.write(f"BLOCK_DOMAIN {rule_val}\n")

    cmd = [DPI_ENGINE_PATH, input_pcap, output_pcap, "--config", rules_path]

    logger.info(f"Running DPI Engine: {' '.join(cmd)}")
    
    try:
        # Run the DPI engine subprocess
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            encoding="utf-8",
            errors="ignore",
            check=True
        )
        
        stats = {
            "total_packets": 0,
            "forwarded": 0,
            "dropped": 0,
            "active_flows": 0,
            "app_breakdown": {},
            "ja3_fingerprints": [],
            "beaconing_flows": [],
            "malicious_flows": [],
            "output_file": os.path.basename(output_pcap) if os.path.exists(output_pcap) else None
        }

        for line in result.stdout.splitlines():
            line_raw = line.strip()
            line = line_raw.replace('║', '').replace('╠', '').replace('═', '').replace('╗', '').replace('╔', '').replace('╝', '').replace('╚', '').strip()
            
            if not line:
                continue
                
            if line_raw.startswith("[JA3]"):
                ja3_line = line_raw[6:].strip() # e.g. "192.168.1.5 -> 8.8.8.8 : c1ef87..." (if IP) or "num -> num : hash"
                stats["ja3_fingerprints"].append(ja3_line)
                
                parts = ja3_line.split(" : ")
                if len(parts) == 2:
                    ips = parts[0].split(" -> ")
                    ja3_hash = parts[1].strip()
                    
                    if get_threat_intel().is_ja3_malicious(ja3_hash):
                        stats["malicious_flows"].append({
                            "src": ips[0].strip(),
                            "dst": ips[1].strip(),
                            "ja3": ja3_hash,
                            "threat": "Malicious JA3 Fingerprint"
                        })
            elif line_raw.startswith("[Beaconing]"):
                stats["beaconing_flows"].append(line_raw[12:].strip())
            elif "Total Packets:" in line:
                try: stats["total_packets"] = int(line.split(":")[1].strip())
                except: pass
            elif "Forwarded:" in line:
                try: stats["forwarded"] = int(line.split(":")[1].strip())
                except: pass
            elif "Dropped:" in line:
                try: stats["dropped"] = int(line.split(":")[1].strip())
                except: pass
            elif "Active Flows:" in line:
                try: stats["active_flows"] = int(line.split(":")[1].strip())
                except: pass
            else:
                if "%" in line and not line.startswith("[") and not line.startswith("Output"):
                    parts = line.split()
                    if len(parts) >= 3:
                        app = parts[0]
                        try:
                            for i, part in enumerate(parts):
                                if "%" in part and i > 0:
                                    stats["app_breakdown"][app] = int(parts[i-1])
                                    break
                        except: pass

        return stats
    except subprocess.CalledProcessError as e:
        logger.error(f"DPI Engine failed: {e.stderr}")
        raise RuntimeError(f"DPI Engine execution failed. Check server logs.")
    except Exception as e:
        logger.error(f"Error running DPI engine: {str(e)}")
        raise RuntimeError(f"Error executing DPI engine: {str(e)}")
