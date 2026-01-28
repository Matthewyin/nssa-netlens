from __future__ import annotations
import sys
import json
import argparse

from .analyzer import analyze_pcap


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAP Analyzer CLI")
    parser.add_argument("analysis_type", help="Type of analysis to perform")
    parser.add_argument("filepath", help="Path to PCAP file")
    parser.add_argument(
        "--output-dir", help="Directory to save analysis reports", default=None
    )
    parser.add_argument(
        "--frame", help="Frame number for packet details", type=int, default=None
    )
    parser.add_argument(
        "--search", help="Search query (Tshark display filter)", default=None
    )
    parser.add_argument(
        "--file2", help="Second PCAP file for correlation", default=None
    )
    parser.add_argument("--stream", help="Stream ID for TCP packets", default=None)
    parser.add_argument(
        "--page", help="Page number for pagination", type=int, default=1
    )

    args = parser.parse_args()

    try:
        options = {}
        if args.output_dir:
            options["output_dir"] = args.output_dir
        if args.search:
            options["search_query"] = args.search

        if args.analysis_type == "packet_details":
            if args.frame is None:
                print(json.dumps({"error": "Frame number required (--frame)"}))
                return 1
            from .analyzer import PcapAnalyzer

            analyzer = PcapAnalyzer(args.filepath)
            result = analyzer.get_packet_details(args.frame)
        elif args.analysis_type == "tcp_stream_packets":
            if not args.stream:
                print(json.dumps({"error": "Stream ID required (--stream)"}))
                return 1
            from .analyzer import PcapAnalyzer

            analyzer = PcapAnalyzer(args.filepath)
            result = analyzer.get_tcp_stream_packets(args.stream, args.page)
        elif args.analysis_type == "correlate":
            if not args.file2:
                print(json.dumps({"error": "Second file required (--file2)"}))
                return 1
            from .multi_analyzer import MultiPcapAnalyzer

            analyzer = MultiPcapAnalyzer()
            result = analyzer.correlate(args.filepath, args.file2)
        else:
            result = analyze_pcap(args.filepath, args.analysis_type, options)

        print(json.dumps(result))
        return 0
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {args.filepath}"}))
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
