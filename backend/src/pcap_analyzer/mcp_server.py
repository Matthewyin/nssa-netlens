from mcp.server.fastmcp import FastMCP
from pcap_analyzer.analyzer import PcapAnalyzer
import json

mcp = FastMCP("PCAP Analyzer")


@mcp.tool()
def get_pcap_summary(filepath: str) -> str:
    """
    Get a high-level summary of a PCAP file.

    Args:
        filepath: Absolute path to the .pcap or .pcapng file.

    Returns:
        JSON string containing total packets, duration, protocol distribution, and top talkers.
    """
    try:
        analyzer = PcapAnalyzer(filepath)
        result = analyzer.analyze_summary()
        return json.dumps(result.to_dict(), indent=2)
    except Exception as e:
        return f"Error analyzing file: {str(e)}"


@mcp.tool()
def scan_security_threats(filepath: str) -> str:
    """
    Scan a PCAP file for security threats like SQL injection, XSS, plaintext credentials, and port scans.

    Args:
        filepath: Absolute path to the .pcap or .pcapng file.

    Returns:
        JSON string containing a list of detected alerts with severity and description.
    """
    try:
        analyzer = PcapAnalyzer(filepath)
        result = analyzer.analyze_security()
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error scanning file: {str(e)}"


@mcp.tool()
def analyze_http_traffic(filepath: str) -> str:
    """
    Analyze HTTP traffic in a PCAP file.

    Args:
        filepath: Absolute path to the .pcap or .pcapng file.

    Returns:
        JSON string containing HTTP requests, responses, and top hosts.
    """
    try:
        analyzer = PcapAnalyzer(filepath)
        result = analyzer.analyze_http()
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error analyzing HTTP: {str(e)}"


@mcp.tool()
def analyze_dns_queries(filepath: str) -> str:
    """
    Analyze DNS queries in a PCAP file.

    Args:
        filepath: Absolute path to the .pcap or .pcapng file.

    Returns:
        JSON string containing DNS queries, responses, and top domains.
    """
    try:
        analyzer = PcapAnalyzer(filepath)
        result = analyzer.analyze_dns()
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error analyzing DNS: {str(e)}"


@mcp.tool()
def list_tcp_sessions(filepath: str) -> str:
    """
    List TCP sessions with payload previews.

    Args:
        filepath: Absolute path to the .pcap or .pcapng file.

    Returns:
        JSON string containing a list of TCP sessions with source/dest IPs, ports, and payload previews.
    """
    try:
        analyzer = PcapAnalyzer(filepath)
        result = analyzer.analyze_tcp_sessions()
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error analyzing TCP sessions: {str(e)}"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
