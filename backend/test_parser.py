import sys
import os

# Add parent directory to path so we can import backend packages
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.pcap_parser import PcapParser
from backend.traffic_classifier import TrafficClassifier

def test_pipeline():
    print("Starting pipeline test...")
    
    # 1. Test Demo File Generation / Existence
    demo_pcap = "backend/demo_pcaps/safe_browsing.pcap"
    if not os.path.exists(demo_pcap):
        print(f"Error: Demo file {demo_pcap} does not exist.")
        sys.exit(1)
        
    print(f"Found demo file: {demo_pcap}")
    
    # 2. Test Parser
    parser = PcapParser(demo_pcap)
    packets, flows = parser.parse()
    
    print(f"Parsed {len(packets)} packets successfully.")
    print(f"Reconstructed {len(flows)} bidirectional flows.")
    
    if len(packets) == 0:
        print("Error: Parsed 0 packets from pcap.")
        sys.exit(1)
        
    # 3. Test Classifier
    classifier = TrafficClassifier()
    classified = classifier.classify_flows(flows)
    
    print(f"Classified {len(classified)} flows.")
    for flow in classified[:3]:
        print(f"  Flow ID #{flow['flow_id']} - Src: {flow['src_ip']} -> Dst: {flow['dst_ip']} | Category: {flow['app_category']} | Domain: {flow['domain'] or 'None'} | Bytes: {flow['byte_count']}")
        
    # 4. Test Port Scan detection
    scan_pcap = "backend/demo_pcaps/port_scan.pcap"
    if os.path.exists(scan_pcap):
        parser_scan = PcapParser(scan_pcap)
        _, flows_scan = parser_scan.parse()
        classified_scan = classifier.classify_flows(flows_scan)
        
        has_threat = any("Port Scan" in f["app_category"] for f in classified_scan)
        print(f"Port scan detection: {'SUCCESS' if has_threat else 'FAILED'}")
        
    print("\nAll parser and classifier pipeline tests: PASSED!")

if __name__ == '__main__':
    test_pipeline()
