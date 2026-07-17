import os
import struct
import random

class PCAPGenerator:
    """Helper to generate binary PCAP files for test demos."""
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self.file = open(filepath, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000
        
    def write_global_header(self):
        # Magic number (0xa1b2c3d4), Version 2.4, Snaplen 65535, Ethernet (1)
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()

def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0
    
    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)
    
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    return header

def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)

def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)

def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    extensions = sni_ext
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 2) + struct.pack('>H', 0x1301)
    compression = struct.pack('BB', 1, 0)
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    handshake = struct.pack('B', 0x01)
    handshake += struct.pack('>I', len(client_hello_body))[1:]
    handshake += client_hello_body
    
    record = struct.pack('B', 0x16)
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake
    return record

def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)
    return txid + flags + counts + question

def generate_safe_browsing():
    gen = PCAPGenerator('backend/demo_pcaps/safe_browsing.pcap')
    user_mac = '00:11:22:33:44:55'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    user_ip = '192.168.1.100'
    
    # 1. DNS Queries
    dns_server = '8.8.8.8'
    domains = ['www.google.com', 'wikipedia.org', 'github.com', 'example.com']
    for dom in domains:
        dns_data = create_dns_query(dom)
        eth = create_ethernet_header(user_mac, gateway_mac)
        udp = create_udp_header(49152 + random.randint(1, 1000), 53, len(dns_data))
        ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
        gen.write_packet(eth + ip + udp + dns_data)
        
    # 2. HTTP request (example.com)
    src_port = 50001
    dst_ip = '93.184.216.34'
    
    # SYN
    eth = create_ethernet_header(user_mac, gateway_mac)
    tcp = create_tcp_header(src_port, 80, 100, 0, 0x02)
    ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
    gen.write_packet(eth + ip + tcp)
    
    # HTTP GET
    http_data = create_http_request('example.com')
    tcp = create_tcp_header(src_port, 80, 101, 1, 0x18)
    ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
    gen.write_packet(eth + ip + tcp + http_data)
    
    # 3. HTTPS TLS handshakes for google and github
    https_targets = [('142.250.185.206', 'www.google.com'), ('140.82.114.4', 'github.com')]
    for dst_ip, sni in https_targets:
        src_port += 1
        # SYN
        tcp = create_tcp_header(src_port, 443, 200, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        gen.write_packet(eth + ip + tcp)
        
        # Client Hello
        tls_data = create_tls_client_hello(sni)
        tcp = create_tcp_header(src_port, 443, 201, 1, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        gen.write_packet(eth + ip + tcp + tls_data)
        
    gen.close()

def generate_video_stream():
    gen = PCAPGenerator('backend/demo_pcaps/video_stream.pcap')
    user_mac = '00:11:22:33:44:55'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    user_ip = '192.168.1.100'
    yt_ip = '142.250.185.110'
    src_port = 55000
    
    # Handshake
    eth = create_ethernet_header(user_mac, gateway_mac)
    tcp = create_tcp_header(src_port, 443, 500, 0, 0x02)
    ip = create_ip_header(user_ip, yt_ip, 6, len(tcp))
    gen.write_packet(eth + ip + tcp)
    
    # Client Hello
    tls_data = create_tls_client_hello('www.youtube.com')
    tcp = create_tcp_header(src_port, 443, 501, 1, 0x18)
    ip = create_ip_header(user_ip, yt_ip, 6, len(tcp) + len(tls_data))
    gen.write_packet(eth + ip + tcp + tls_data)
    
    # Simulated Streaming: large incoming payload packets from server to client
    server_eth = create_ethernet_header(gateway_mac, user_mac)
    for i in range(15):
        # Data packet from YouTube server (length 1460 bytes payload)
        payload = bytes([random.randint(0, 255) for _ in range(1300)])
        tcp = create_tcp_header(443, src_port, 1000 + i*1300, 501 + len(tls_data), 0x10)
        ip = create_ip_header(yt_ip, user_ip, 6, len(tcp) + len(payload))
        gen.write_packet(server_eth + ip + tcp + payload)
        
    gen.close()

def generate_port_scan():
    gen = PCAPGenerator('backend/demo_pcaps/port_scan.pcap')
    attacker_mac = '00:aa:bb:cc:dd:ee'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    attacker_ip = '192.168.1.222'
    target_ip = '192.168.1.1'
    
    # Attacker scans ports 20 to 100
    eth = create_ethernet_header(attacker_mac, gateway_mac)
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]:
        src_port = random.randint(30000, 60000)
        tcp = create_tcp_header(src_port, port, random.randint(1000, 5000), 0, 0x02) # TCP SYN
        ip = create_ip_header(attacker_ip, target_ip, 6, len(tcp))
        gen.write_packet(eth + ip + tcp)
        
    gen.close()

if __name__ == '__main__':
    print("Generating demo PCAPs...")
    generate_safe_browsing()
    generate_video_stream()
    generate_port_scan()
    print("Finished generating PCAP demo files.")
