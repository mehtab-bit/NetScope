import struct
import socket
import os
from typing import Dict, List, Tuple, Optional

class PcapParser:
    """
    A pure Python PCAP parser that extracts packet headers,
    identifies TLS SNI, HTTP Host, and DNS queries, and aggregates
    flows and network statistics.
    """
    
    @staticmethod
    def parse_mac(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def parse_ip(ip_bytes: bytes) -> str:
        return ".".join(str(b) for b in ip_bytes)

    @staticmethod
    def extract_sni(payload: bytes) -> Optional[str]:
        """Extracts Server Name Indication (SNI) from TLS Client Hello payload."""
        try:
            # TLS Handshake Content Type (0x16) and Client Hello Handshake Type (0x01)
            if len(payload) < 9:
                return None
            if payload[0] != 0x16:  # Handshake record
                return None
            
            # Version check (bytes 1-2)
            version = struct.unpack(">H", payload[1:3])[0]
            if version < 0x0300 or version > 0x0304:
                return None
                
            record_len = struct.unpack(">H", payload[3:5])[0]
            if record_len > len(payload) - 5:
                return None
                
            if payload[5] != 0x01:  # Handshake type: Client Hello
                return None
                
            # Handshake body starts at offset 5
            offset = 5
            handshake_len = (payload[offset+1] << 16) | (payload[offset+2] << 8) | payload[offset+3]
            offset += 4  # Skip handshake type and length
            
            # Skip Client Version (2 bytes) + Random (32 bytes)
            offset += 34
            
            # Session ID (1 byte length + variable bytes)
            if offset >= len(payload):
                return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            # Cipher Suites (2 bytes length + variable bytes)
            if offset + 2 > len(payload):
                return None
            cipher_suites_len = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            # Compression Methods (1 byte length + variable bytes)
            if offset >= len(payload):
                return None
            compression_len = payload[offset]
            offset += 1 + compression_len
            
            # Extensions (2 bytes length + variable extensions)
            if offset + 2 > len(payload):
                return None
            extensions_len = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            
            extensions_end = offset + extensions_len
            if extensions_end > len(payload):
                extensions_end = len(payload)
                
            # Parse extensions to find SNI (0x0000)
            while offset + 4 <= extensions_end:
                ext_type = struct.unpack(">H", payload[offset:offset+2])[0]
                ext_len = struct.unpack(">H", payload[offset+2:offset+4])[0]
                offset += 4
                
                if offset + ext_len > extensions_end:
                    break
                    
                if ext_type == 0x0000:  # SNI extension
                    if ext_len < 5:
                        break
                    sni_list_len = struct.unpack(">H", payload[offset:offset+2])[0]
                    if sni_list_len < 3:
                        break
                        
                    sni_type = payload[offset+2]
                    sni_len = struct.unpack(">H", payload[offset+3:offset+5])[0]
                    
                    if sni_type == 0x00 and sni_len <= ext_len - 5:  # Hostname
                        sni_bytes = payload[offset+5 : offset+5+sni_len]
                        return sni_bytes.decode("ascii", errors="ignore")
                
                offset += ext_len
        except Exception:
            pass
        return None

    @staticmethod
    def extract_http_host(payload: bytes) -> Optional[str]:
        """Extracts Host header value from plain HTTP payload."""
        try:
            methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
            if len(payload) < 10 or not any(payload.startswith(m) for m in methods):
                return None
                
            # Search for Host: header case-insensitively
            host_idx = payload.lower().find(b"\r\nhost:")
            if host_idx == -1:
                # Could be the very first header line (unlikely, but check)
                if payload.lower().startswith(b"host:"):
                    host_idx = 0
                else:
                    return None
            else:
                host_idx += 2  # skip CRLF
                
            # Find end of Host header line
            start = host_idx + 5  # skip "host:"
            while start < len(payload) and payload[start] in (32, 9):  # skip spaces/tabs
                start += 1
                
            end = payload.find(b"\r", start)
            if end == -1:
                end = payload.find(b"\n", start)
            if end == -1:
                end = len(payload)
                
            host = payload[start:end].decode("ascii", errors="ignore").strip()
            # Remove port if present
            if ":" in host:
                host = host.split(":")[0]
            return host
        except Exception:
            pass
        return None

    @staticmethod
    def extract_dns_query(payload: bytes) -> Optional[str]:
        """Extracts domain query name from DNS packet (port 53)."""
        try:
            if len(payload) < 12:
                return None
            
            flags = struct.unpack(">H", payload[2:4])[0]
            # QR bit: bit 15 (should be 0 for queries)
            is_response = (flags & 0x8000) != 0
            if is_response:
                return None
                
            qd_count = struct.unpack(">H", payload[4:6])[0]
            if qd_count == 0:
                return None
                
            # Parse QNAME label-by-label starting at byte 12
            offset = 12
            labels = []
            
            while offset < len(payload):
                label_len = payload[offset]
                if label_len == 0:
                    break
                if label_len > 63:
                    # Compression pointer or invalid label
                    break
                offset += 1
                if offset + label_len > len(payload):
                    break
                label = payload[offset:offset+label_len].decode("ascii", errors="ignore")
                labels.append(label)
                offset += label_len
                
            if labels:
                return ".".join(labels)
        except Exception:
            pass
        return None

    def __init__(self, filename: str):
        self.filename = filename
        self.packets = []
        self.flows = {}  # key: 5-tuple, value: flow state dict
        self.total_packets = 0
        self.parse_errors = 0
        
    def parse(self) -> Tuple[List[dict], List[dict]]:
        """
        Parses the PCAP file. Returns a tuple of:
        1. List of parsed packets (for debugging/detailed views)
        2. List of summarized flows (for local ML and reporting)
        """
        if not os.path.exists(self.filename):
            raise FileNotFoundError(f"File not found: {self.filename}")
            
        with open(self.filename, "rb") as f:
            # 1. Read Global Header (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                return [], []
                
            magic_number = struct.unpack("<I", global_header[0:4])[0]
            # Detect endianness
            is_little_endian = True
            if magic_number == 0xa1b2c3d4:
                is_little_endian = True
            elif magic_number == 0xd4c3b2a1:
                is_little_endian = False
            else:
                # Unsupported PCAP version or format
                raise ValueError("Invalid or unsupported PCAP magic number.")
                
            fmt_packet_hdr = "<IIII" if is_little_endian else ">IIII"
            
            packet_id = 0
            while True:
                # 2. Read Packet Header (16 bytes)
                hdr_bytes = f.read(16)
                if len(hdr_bytes) < 16:
                    break
                    
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt_packet_hdr, hdr_bytes)
                
                # Read Packet Data
                data_bytes = f.read(incl_len)
                if len(data_bytes) < incl_len:
                    break
                    
                packet_id += 1
                self.total_packets += 1
                
                # Parse packet layers
                try:
                    parsed = self._parse_packet_layers(packet_id, ts_sec, ts_usec, data_bytes)
                    if parsed:
                        self.packets.append(parsed)
                        self._add_to_flow(parsed)
                    else:
                        self.parse_errors += 1
                except Exception:
                    self.parse_errors += 1
                    
        # Format the final flows as a list of dicts
        flow_list = []
        for flow_key, flow_data in self.flows.items():
            # Compute stats
            lengths = flow_data["packet_lengths"]
            flow_data["mean_packet_size"] = sum(lengths) / len(lengths) if lengths else 0
            flow_data["max_packet_size"] = max(lengths) if lengths else 0
            flow_data["min_packet_size"] = min(lengths) if lengths else 0
            flow_data["byte_count"] = sum(lengths)
            flow_data["packet_count"] = len(lengths)
            flow_data["duration"] = flow_data["last_seen"] - flow_data["first_seen"]
            
            # Identify most likely domain/SNI
            flow_data["domain"] = flow_data["sni"] or flow_data["http_host"] or flow_data["dns_query"] or ""
            
            flow_list.append({
                "flow_id": flow_data["flow_id"],
                "src_ip": flow_key[0],
                "dst_ip": flow_key[1],
                "src_port": flow_key[2],
                "dst_port": flow_key[3],
                "protocol": flow_key[4],
                "packet_count": flow_data["packet_count"],
                "byte_count": flow_data["byte_count"],
                "duration": round(flow_data["duration"], 4),
                "mean_packet_size": round(flow_data["mean_packet_size"], 2),
                "max_packet_size": flow_data["max_packet_size"],
                "min_packet_size": flow_data["min_packet_size"],
                "domain": flow_data["domain"],
                "app_category": flow_data["app_category"],
                "first_seen": flow_data["first_seen"],
                "last_seen": flow_data["last_seen"],
            })
            
        return self.packets, flow_list

    def _parse_packet_layers(self, packet_id: int, ts_sec: int, ts_usec: int, data: bytes) -> Optional[dict]:
        """Parses Ethernet, IPv4, TCP/UDP headers and payloads."""
        if len(data) < 14:
            return None
            
        # 1. Ethernet Header
        dest_mac = self.parse_mac(data[0:6])
        src_mac = self.parse_mac(data[6:12])
        ether_type = struct.unpack(">H", data[12:14])[0]
        
        offset = 14
        if ether_type != 0x0800:
            # Only support IPv4 for this analyzer
            return None
            
        # 2. IPv4 Header
        if len(data) < offset + 20:
            return None
            
        version_ihl = data[offset]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        
        if version != 4 or len(data) < offset + ip_header_len:
            return None
            
        ttl = data[offset + 8]
        protocol = data[offset + 9]
        src_ip = self.parse_ip(data[offset + 12 : offset + 16])
        dst_ip = self.parse_ip(data[offset + 16 : offset + 20])
        
        offset += ip_header_len
        
        # 3. Transport Layer
        src_port = 0
        dst_port = 0
        protocol_str = "Unknown"
        payload_data = b""
        tcp_flags = 0
        tcp_flags_str = ""
        
        if protocol == 6:  # TCP
            if len(data) < offset + 20:
                return None
            src_port, dst_port = struct.unpack(">HH", data[offset : offset + 4])
            data_offset = (data[offset + 12] >> 4) & 0x0F
            tcp_header_len = data_offset * 4
            tcp_flags = data[offset + 13]
            
            # Flags parsing
            flags_list = []
            if tcp_flags & 0x02: flags_list.append("SYN")
            if tcp_flags & 0x10: flags_list.append("ACK")
            if tcp_flags & 0x01: flags_list.append("FIN")
            if tcp_flags & 0x04: flags_list.append("RST")
            if tcp_flags & 0x08: flags_list.append("PSH")
            if tcp_flags & 0x20: flags_list.append("URG")
            tcp_flags_str = "|".join(flags_list) if flags_list else "None"
            
            payload_offset = offset + tcp_header_len
            if len(data) > payload_offset:
                payload_data = data[payload_offset:]
            protocol_str = "TCP"
            
        elif protocol == 17:  # UDP
            if len(data) < offset + 8:
                return None
            src_port, dst_port = struct.unpack(">HH", data[offset : offset + 4])
            payload_offset = offset + 8
            if len(data) > payload_offset:
                payload_data = data[payload_offset:]
            protocol_str = "UDP"
            
        else:
            return None  # Only parse TCP/UDP for flow reconstruction
            
        # 4. Deep Packet Inspection (DPI)
        sni = None
        http_host = None
        dns_query = None
        
        if dst_port == 443 or src_port == 443:
            sni = self.extract_sni(payload_data)
        if dst_port == 80 or src_port == 80:
            http_host = self.extract_http_host(payload_data)
        if dst_port == 53 or src_port == 53:
            dns_query = self.extract_dns_query(payload_data)
            
        timestamp = ts_sec + (ts_usec / 1000000.0)
        
        return {
            "packet_id": packet_id,
            "timestamp": timestamp,
            "src_mac": src_mac,
            "dst_mac": dest_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_str,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags_str,
            "length": len(data),
            "payload_length": len(payload_data),
            "sni": sni,
            "http_host": http_host,
            "dns_query": dns_query,
        }

    def _add_to_flow(self, packet: dict):
        """Assembles packets into flows by tracking connection keys."""
        # Define key based on 5-tuple
        key = (packet["src_ip"], packet["dst_ip"], packet["src_port"], packet["dst_port"], packet["protocol"])
        rev_key = (packet["dst_ip"], packet["src_ip"], packet["dst_port"], packet["src_port"], packet["protocol"])
        
        # Check if flow exists in either direction
        target_key = None
        if key in self.flows:
            target_key = key
        elif rev_key in self.flows:
            target_key = rev_key
        else:
            # Create new flow
            target_key = key
            flow_id = len(self.flows) + 1
            self.flows[key] = {
                "flow_id": flow_id,
                "first_seen": packet["timestamp"],
                "last_seen": packet["timestamp"],
                "packet_lengths": [],
                "sni": None,
                "http_host": None,
                "dns_query": None,
                "app_category": "UNKNOWN",
            }
            
        flow = self.flows[target_key]
        flow["last_seen"] = packet["timestamp"]
        flow["packet_lengths"].append(packet["length"])
        
        # Capture SNI, Host, or DNS if discovered in this packet
        if packet["sni"]:
            flow["sni"] = packet["sni"]
            flow["app_category"] = self._map_domain_to_app(packet["sni"])
        if packet["http_host"]:
            flow["http_host"] = packet["http_host"]
            flow["app_category"] = self._map_domain_to_app(packet["http_host"])
        if packet["dns_query"]:
            flow["dns_query"] = packet["dns_query"]
            # Keep app as DNS if it hasn't matched anything more specific
            if flow["app_category"] == "UNKNOWN":
                flow["app_category"] = "DNS"
                
    def _map_domain_to_app(self, domain: str) -> str:
        """Simple mapping of domain names to human-readable App Category names."""
        dom = domain.lower()
        if "youtube" in dom or "googlevideo" in dom:
            return "YouTube"
        elif "facebook" in dom or "messenger" in dom:
            return "Facebook"
        elif "instagram" in dom:
            return "Instagram"
        elif "google" in dom or "gstatic" in dom:
            return "Google"
        elif "netflix" in dom:
            return "Netflix"
        elif "twitter" in dom or "t.co" in dom or "x.com" in dom:
            return "Twitter/X"
        elif "tiktok" in dom:
            return "TikTok"
        elif "spotify" in dom:
            return "Spotify"
        elif "github" in dom:
            return "GitHub"
        elif "discord" in dom:
            return "Discord"
        elif "telegram" in dom:
            return "Telegram"
        elif "microsoft" in dom or "live.com" in dom:
            return "Microsoft"
        elif "apple" in dom or "icloud" in dom:
            return "Apple"
        elif "amazon" in dom or "aws" in dom:
            return "Amazon"
        elif "zoom" in dom:
            return "Zoom"
        return "HTTPS/Web" if "http" in dom or "." in dom else "UNKNOWN"
