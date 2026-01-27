from pcap_analyzer.tshark import tshark

print(f"Tshark available: {tshark.is_available()}")
print(f"Path: {tshark.tshark_path}")
print(f"Version: {tshark.get_version()}")
