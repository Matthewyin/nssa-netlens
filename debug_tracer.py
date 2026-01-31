import sys
import os
import json
from dataclasses import asdict

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "backend/src"))

from pcap_analyzer.link_tracer import LinkTracer


def test_trace():
    tracer = LinkTracer()
    file_path = os.path.abspath("tests/test.pcapng")

    print(f"Testing with file: {file_path}")

    # Test single file trace first
    result = tracer.trace_single_file(file_path)

    chains = result.get("chains", [])
    print(f"Found {len(chains)} chains")

    if chains:
        first_chain = chains[0]
        print(f"Chain 1 hops: {len(first_chain['hops'])}")
        if first_chain["hops"]:
            hop = first_chain["hops"][0]
            print(f"Hop 1 packets count: {len(hop['packets'])}")
            if hop["packets"]:
                print("First packet sample:", hop["packets"][0])
            else:
                print("WARNING: Hop 1 has NO packets!")

    # Test multi file (using same file twice for testing)
    print("\nTesting multi-file trace...")
    result_multi = tracer.trace_multi_file(file_path, file_path)
    chains_multi = result_multi.get("chains", [])
    print(f"Found {len(chains_multi)} multi-file chains")

    if chains_multi:
        first_chain = chains_multi[0]
        if first_chain["hops"]:
            hop = first_chain["hops"][0]
            print(f"Multi-file Hop 1 packets count: {len(hop['packets'])}")
            if not hop["packets"]:
                print("WARNING: Multi-file Hop has NO packets!")


if __name__ == "__main__":
    test_trace()
