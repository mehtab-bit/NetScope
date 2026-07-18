import subprocess
import os
import sys
import json
import logging
from typing import Dict, Any, List

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

    cmd = [DPI_ENGINE_PATH, input_pcap, output_pcap]

    for rule in rules:
        rule_type = rule.get("type")
        rule_val = rule.get("value")
        
        if rule_type == "IP":
            cmd.extend(["--block-ip", rule_val])
        elif rule_type == "App":
            cmd.extend(["--block-app", rule_val])
        elif rule_type == "Domain":
            cmd.extend(["--block-domain", rule_val])

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
        
        # We need to parse the stdout of the C++ engine to return stats
        # The C++ engine prints lines like:
        # [Stats] Total Packets: 45
        # [Stats] Forwarded: 40
        # [Stats] Dropped: 5
        # [Stats] Active Flows: 12
        # [App] HTTP: 30
        
        stats = {
            "total_packets": 0,
            "forwarded": 0,
            "dropped": 0,
            "active_flows": 0,
            "app_breakdown": {},
            "output_file": os.path.basename(output_pcap) if os.path.exists(output_pcap) else None
        }

        for line in result.stdout.splitlines():
            # Clean up the line by removing the borders and trimming
            line = line.replace('║', '').replace('╠', '').replace('═', '').replace('╗', '').replace('╔', '').replace('╝', '').replace('╚', '').strip()
            
            if not line:
                continue
                
            if "Total Packets:" in line:
                try:
                    stats["total_packets"] = int(line.split(":")[1].strip())
                except: pass
            elif "Forwarded:" in line:
                try:
                    stats["forwarded"] = int(line.split(":")[1].strip())
                except: pass
            elif "Dropped:" in line:
                try:
                    stats["dropped"] = int(line.split(":")[1].strip())
                except: pass
            elif "Active Flows:" in line:
                try:
                    stats["active_flows"] = int(line.split(":")[1].strip())
                except: pass
            else:
                # App breakdown lines look like: HTTPS                39  50.6% ##########
                # or [Detected Applications/Domains] which we want to ignore
                if "%" in line and not line.startswith("[") and not line.startswith("Output"):
                    # Extract application and count
                    parts = line.split()
                    if len(parts) >= 3:
                        app = parts[0]
                        # The count is the number right before the percentage
                        try:
                            # Iterate backwards to find the percentage, the element before it is the count
                            for i, part in enumerate(parts):
                                if "%" in part and i > 0:
                                    count = int(parts[i-1])
                                    stats["app_breakdown"][app] = count
                                    break
                        except:
                            pass

        return stats

    except subprocess.CalledProcessError as e:
        logger.error(f"DPI Engine failed with exit code {e.returncode}")
        logger.error(f"Stderr: {e.stderr}")
        raise RuntimeError(f"DPI Engine execution failed. Check server logs.")
    except Exception as e:
        logger.error(f"Error running DPI engine: {str(e)}")
        raise RuntimeError(f"Error executing DPI engine: {str(e)}")
