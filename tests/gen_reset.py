from scapy.all import Ether, IP, TCP, wrpcap
import os

# Create a packet with RESET flag
pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags="R", seq=100)

output_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "reset_test.pcap"
)
wrpcap(output_path, [pkt])
print(f"Created {output_path}")
