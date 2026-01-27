from scapy.all import Ether, IP, TCP, Raw, wrpcap

packets = []

# 1. Plaintext Auth
packets.append(
    Ether()
    / IP(dst="1.2.3.4", src="192.168.1.100")
    / TCP(dport=80)
    / Raw(load="GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n")
)

# 2. SQL Injection
packets.append(
    Ether()
    / IP(dst="1.2.3.4", src="192.168.1.101")
    / TCP(dport=80)
    / Raw(load="GET /users?id=' OR '1'='1 HTTP/1.1\r\n\r\n")
)

# 3. XSS
packets.append(
    Ether()
    / IP(dst="1.2.3.4", src="192.168.1.102")
    / TCP(dport=80)
    / Raw(load="POST /comment HTTP/1.1\r\n\r\n<script>alert(1)</script>")
)

# 4. Port Scan (25 SYN packets to different ports)
for port in range(1000, 1025):
    packets.append(
        Ether() / IP(src="6.6.6.6", dst="1.2.3.4") / TCP(dport=port, flags="S")
    )

import os

output_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "attack_test.pcap"
)
wrpcap(output_path, packets)
print(f"Created {output_path}")
