from __future__ import annotations
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class PacketSummary:
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0


@dataclass
class ProtocolStats:
    name: str
    count: int
    percentage: float


@dataclass
class TalkerStats:
    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class TimelinePoint:
    time: str
    bytes: int
    packets: int


@dataclass
class SecurityAlert:
    severity: str
    alert_type: str
    description: str
    source_ip: str
    target_ip: str | None = None
    payload_preview: str | None = None


@dataclass
class TcpSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int
    byte_count: int
    duration: float
    start_time: float
    payload_ascii: str
    payload_hex: str
    protocol: str = "TCP"
    summary: str = ""
    is_binary: bool = False


@dataclass
class AnalysisResult:
    summary: PacketSummary = field(default_factory=PacketSummary)
    protocols: list[ProtocolStats] = field(default_factory=list)
    top_talkers: list[TalkerStats] = field(default_factory=list)
    timeline: list[TimelinePoint] = field(default_factory=list)
    security_alerts: list[SecurityAlert] = field(default_factory=list)
    tcp_sessions: list[TcpSession] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": asdict(self.summary),
            "protocols": [asdict(p) for p in self.protocols],
            "top_talkers": [asdict(t) for t in self.top_talkers],
            "timeline": [asdict(t) for t in self.timeline],
            "security_alerts": [asdict(a) for a in self.security_alerts],
            "tcp_sessions": [asdict(s) for s in self.tcp_sessions],
        }


class PcapAnalyzer:
    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)

    def _save_report(
        self, data: dict, report_type: str, output_dir: str | None = None
    ) -> None:
        try:
            if output_dir:
                save_dir = Path(output_dir)
            else:
                save_dir = Path(self.filepath).parent / "analysis_reports"

            save_dir.mkdir(parents=True, exist_ok=True)
            report_path = save_dir / f"{report_type}_{Path(self.filepath).name}.json"

            if "scan_time" not in data:
                import time

                data["scan_time"] = str(time.time())

            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            data["saved_path"] = str(report_path)
        except Exception as e:
            data["save_error"] = str(e)
            import sys

            print(f"Error saving {report_type} report: {e}", file=sys.stderr)

    def _build_filter(self, base_filter: str, search_query: str | None) -> str:
        if not search_query:
            return base_filter
        return f"({base_filter}) and ({search_query})"

    def _is_binary(self, data: bytes) -> bool:
        if not data:
            return False
        # Count non-printable chars (excluding common whitespace)
        # Printable: 32-126. Whitespace: 9, 10, 13.
        text_chars = bytearray(
            {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
        )
        return bool(data.translate(None, text_chars))

    def analyze_summary(self) -> AnalysisResult:
        from .tshark import tshark

        if not tshark.is_available():
            return AnalysisResult()

        result = AnalysisResult()

        fields = [
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "_ws.col.protocol",
        ]

        protocol_counter: Counter[str] = Counter()
        ip_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"sent": 0, "received": 0, "bytes_sent": 0, "bytes_received": 0}
        )

        timestamps = []
        total_bytes = 0
        total_packets = 0

        # Timeline buckets (1 second resolution)
        timeline_buckets: dict[int, dict[str, int]] = defaultdict(
            lambda: {"bytes": 0, "packets": 0}
        )
        start_time = None

        try:
            for row in tshark.stream_fields(str(self.filepath), fields):
                total_packets += 1
                pkt_len = int(row.get("frame.len", 0))
                total_bytes += pkt_len

                # Time
                try:
                    ts = float(row.get("frame.time_epoch", 0))
                    if start_time is None:
                        start_time = int(ts)
                        timestamps.append(ts)  # First
                    timestamps.append(
                        ts
                    )  # Keep track for min/max logic below if needed
                    # Optimization: Just track min/max without list if huge?
                    # But existing logic used list for min/max.

                    bucket_ts = int(ts) - start_time
                    if bucket_ts >= 0:
                        timeline_buckets[bucket_ts]["bytes"] += pkt_len
                        timeline_buckets[bucket_ts]["packets"] += 1
                except (ValueError, TypeError):
                    pass

                # Protocol
                proto = row.get("_ws.col.protocol", "Unknown")
                protocol_counter[proto] += 1

                # IP
                src = row.get("ip.src") or row.get("ipv6.src")
                dst = row.get("ip.dst") or row.get("ipv6.dst")

                if src:
                    # Handle multiple IPs in one packet (e.g. tunneling)
                    for s in src.split(","):
                        ip_stats[s]["sent"] += 1
                        ip_stats[s]["bytes_sent"] += pkt_len
                if dst:
                    for d in dst.split(","):
                        ip_stats[d]["received"] += 1
                        ip_stats[d]["bytes_received"] += pkt_len

        except Exception as e:
            print(f"Summary analysis error: {e}")

        result.summary = PacketSummary(
            total_packets=total_packets,
            total_bytes=total_bytes,
            first_timestamp=min(timestamps) if timestamps else 0.0,
            last_timestamp=max(timestamps) if timestamps else 0.0,
            duration_seconds=round(max(timestamps) - min(timestamps), 3)
            if len(timestamps) > 1
            else 0.0,
        )

        result.protocols = [
            ProtocolStats(
                name=name,
                count=count,
                percentage=round(count / total_packets * 100, 1)
                if total_packets
                else 0.0,
            )
            for name, count in protocol_counter.most_common(10)
        ]

        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]["sent"] + x[1]["received"],
            reverse=True,
        )[:10]

        result.top_talkers = [
            TalkerStats(
                ip=ip,
                packets_sent=stats["sent"],
                packets_received=stats["received"],
                bytes_sent=stats["bytes_sent"],
                bytes_received=stats["bytes_received"],
            )
            for ip, stats in sorted_ips
        ]

        # Populate timeline (limit to 50 points to prevent overload)
        sorted_buckets = sorted(timeline_buckets.items())
        total_buckets = len(sorted_buckets)

        if total_buckets > 50:
            # Resample if too many points
            step = total_buckets / 50
            timeline_data = []
            for i in range(50):
                idx = int(i * step)
                if idx < total_buckets:
                    ts, data = sorted_buckets[idx]
                    timeline_data.append(
                        TimelinePoint(
                            time=f"{ts}s", bytes=data["bytes"], packets=data["packets"]
                        )
                    )
            result.timeline = timeline_data
        else:
            result.timeline = [
                TimelinePoint(
                    time=f"{ts}s", bytes=data["bytes"], packets=data["packets"]
                )
                for ts, data in sorted_buckets
            ]

        return result

    def analyze_http(self, search_query: str | None = None) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {}

        fields = [
            "frame.number",
            "tcp.stream",
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.response.code",
            "http.user_agent",
            "http.content_type",
        ]

        display_filter = self._build_filter("http", search_query)

        try:
            packets = tshark.run_json(
                str(self.filepath), display_filter=display_filter, fields=fields
            )
        except Exception as e:
            return {"error": str(e)}

        requests = []
        host_counter: Counter[str] = Counter()
        total_requests = 0
        total_responses = 0

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            if not layers:
                continue

            method = layers.get("http.request.method", [None])[0]
            host = layers.get("http.host", [None])[0]
            uri = layers.get("http.request.uri", [None])[0]
            code = layers.get("http.response.code", [None])[0]
            ua = layers.get("http.user_agent", [None])[0]
            ctype = layers.get("http.content_type", [None])[0]
            frame = layers.get("frame.number", ["0"])[0]
            stream = layers.get("tcp.stream", ["0"])[0]

            if method:
                total_requests += 1
                requests.append(
                    {
                        "frame": frame,
                        "stream": stream,
                        "method": method,
                        "host": host or "",
                        "path": uri or "",
                        "ua": ua or "",
                        "type": "request",
                    }
                )
                if host:
                    host_counter[host] += 1

            if code:
                total_responses += 1
                requests.append(
                    {
                        "frame": frame,
                        "stream": stream,
                        "status": code,
                        "ctype": ctype or "",
                        "type": "response",
                    }
                )

        return {
            "total_requests": total_requests,
            "total_responses": total_responses,
            "unique_hosts": len(host_counter),
            "requests": requests[:200],  # Limit output
            "top_hosts": [
                {"host": h, "count": c} for h, c in host_counter.most_common(10)
            ],
        }

    def analyze_dns(self, search_query: str | None = None) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {}

        fields = [
            "frame.number",
            "dns.id",
            "dns.qry.name",
            "dns.qry.type",
            "dns.flags.response",
            "dns.flags.rcode",
            "dns.a",
            "dns.aaaa",
            "dns.cname",
        ]

        display_filter = self._build_filter("dns", search_query)

        try:
            packets = tshark.run_json(
                str(self.filepath), display_filter=display_filter, fields=fields
            )
        except Exception as e:
            return {"error": str(e)}

        queries = []
        domain_counter: Counter[str] = Counter()
        total_queries = 0
        total_responses = 0

        # Tshark query types map (1=A, 28=AAAA, etc). Tshark usually outputs '1' not 'A'.
        # We might need a map or use tshark's resolved values if we didn't use -T fields-like extraction?
        # With -T json -e dns.qry.type, it outputs value.
        # Actually Tshark JSON often has "dns.qry.type": "1".

        dns_type_map = {
            "1": "A",
            "2": "NS",
            "5": "CNAME",
            "6": "SOA",
            "12": "PTR",
            "15": "MX",
            "16": "TXT",
            "28": "AAAA",
            "33": "SRV",
            "255": "ANY",
        }

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            if not layers:
                continue

            is_response = layers.get("dns.flags.response", ["0"])[0] == "1"
            qname = layers.get("dns.qry.name", [None])[0]
            qtype_val = layers.get("dns.qry.type", ["0"])[0]
            qtype = dns_type_map.get(qtype_val, qtype_val)
            tx_id = layers.get("dns.id", ["0"])[0]
            frame = layers.get("frame.number", ["0"])[0]
            rcode = layers.get("dns.flags.rcode", ["0"])[0]

            if not is_response and qname:
                total_queries += 1
                domain_counter[qname] += 1
                queries.append(
                    {
                        "frame": frame,
                        "id": tx_id,
                        "domain": qname,
                        "type": qtype,
                        "answers": [],
                        "is_response": False,
                    }
                )

            elif is_response:
                total_responses += 1
                # Collect answers
                answers = []
                if "dns.a" in layers:
                    answers.extend(layers["dns.a"])
                if "dns.aaaa" in layers:
                    answers.extend(layers["dns.aaaa"])
                if "dns.cname" in layers:
                    answers.extend(layers["dns.cname"])

                if qname:
                    queries.append(
                        {
                            "frame": frame,
                            "id": tx_id,
                            "domain": qname,
                            "type": qtype,
                            "answers": answers,
                            "rcode": rcode,
                            "is_response": True,
                        }
                    )

        return {
            "total_queries": total_queries,
            "total_responses": total_responses,
            "unique_domains": len(domain_counter),
            "queries": queries[:200],
            "top_domains": [
                {"domain": d, "count": c} for d, c in domain_counter.most_common(10)
            ],
        }

    def analyze_tls(self) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {}

        fields = [
            "tls.handshake.type",
            "tls.handshake.version",
            "tls.handshake.extensions_server_name",
            "tls.handshake.ciphersuite",
        ]

        try:
            packets = tshark.run_json(
                str(self.filepath), display_filter="tls.handshake", fields=fields
            )
        except Exception as e:
            return {"error": str(e)}

        handshakes = []
        sni_counter: Counter[str] = Counter()
        version_counter: Counter[str] = Counter()

        tls_version_map = {
            "0x0301": "TLS 1.0",
            "0x0302": "TLS 1.1",
            "0x0303": "TLS 1.2",
            "0x0304": "TLS 1.3",
        }

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            if not layers:
                continue

            hs_type = layers.get("tls.handshake.type", ["0"])[0]
            version_hex = layers.get("tls.handshake.version", [""])[0]
            # Tshark usually outputs hex like 0x0303
            version = tls_version_map.get(version_hex, version_hex or "Unknown")

            if hs_type == "1":  # Client Hello
                sni = layers.get("tls.handshake.extensions_server_name", [None])[0]
                handshakes.append(
                    {
                        "sni": sni,
                        "version": version,
                        "type": "ClientHello",
                        "cipher": None,
                    }
                )
                if sni:
                    sni_counter[sni] += 1
                version_counter[version] += 1

            elif hs_type == "2":  # Server Hello
                cipher = layers.get("tls.handshake.ciphersuite", [None])[0]
                handshakes.append(
                    {
                        "sni": None,
                        "version": version,
                        "type": "ServerHello",
                        "cipher": cipher,
                    }
                )
                version_counter[version] += 1

        return {
            "total_handshakes": len(handshakes),
            "unique_sni": len(sni_counter),
            "handshakes": handshakes[:30],
            "top_sni": [{"sni": s, "count": c} for s, c in sni_counter.most_common(10)],
            "versions": dict(version_counter),
        }

    def analyze_security(self) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {}

        alerts = []

        # 1. Port Scan Detection (SYN packets)
        syn_tracker: dict[str, set[str]] = defaultdict(set)
        for row in tshark.stream_fields(
            str(self.filepath),
            ["ip.src", "tcp.dstport"],
            display_filter="tcp.flags.syn==1 and tcp.flags.ack==0",
        ):
            src = row.get("ip.src")
            port = row.get("tcp.dstport")
            if src and port:
                syn_tracker[src].add(port)

        for src_ip, ports in syn_tracker.items():
            if len(ports) > 20:
                alerts.append(
                    SecurityAlert(
                        severity="Medium",
                        alert_type="Port Scan",
                        description=f"Potential port scan detected ({len(ports)} distinct ports)",
                        source_ip=src_ip,
                        target_ip="Multiple",
                        payload_preview=f"Ports: {list(ports)[:10]}...",
                    )
                )

        # 2. Payload Analysis (SQLi, XSS, Auth)
        sqli_patterns = [
            r"union\s+select",
            r"'\s+or\s+'1'='1",
            r'"\s+or\s+"1"="1',
            r"information_schema",
            r"waitfor\s+delay",
        ]
        xss_patterns = [
            r"<script>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"alert\(",
        ]

        # Stream payload (only packets with data)
        for row in tshark.stream_fields(
            str(self.filepath),
            ["ip.src", "ip.dst", "tcp.payload"],
            display_filter="tcp.len > 0",
        ):
            payload_hex = row.get("tcp.payload")
            if not payload_hex:
                continue

            try:
                # Tshark returns AA:BB:CC, need to strip colons
                payload = bytes.fromhex(payload_hex.replace(":", "")).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                continue

            src_ip = row.get("ip.src", "Unknown")
            dst_ip = row.get("ip.dst", "Unknown")
            lower_payload = payload.lower()

            # Plaintext Auth
            if "Authorization: Basic" in payload:
                alerts.append(
                    SecurityAlert(
                        severity="High",
                        alert_type="Plaintext Credentials",
                        description="Basic Authentication header found",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        payload_preview=payload[:100],
                    )
                )

            # SQL Injection
            for pattern in sqli_patterns:
                if re.search(pattern, lower_payload):
                    alerts.append(
                        SecurityAlert(
                            severity="High",
                            alert_type="SQL Injection",
                            description=f"SQL Injection pattern detected: {pattern}",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            payload_preview=payload[:100],
                        )
                    )
                    break

            # XSS
            for pattern in xss_patterns:
                if re.search(pattern, lower_payload):
                    alerts.append(
                        SecurityAlert(
                            severity="Medium",
                            alert_type="XSS",
                            description=f"Cross-Site Scripting pattern detected: {pattern}",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            payload_preview=payload[:100],
                        )
                    )
                    break

        # Deduplicate alerts
        unique_alerts = []
        seen = set()
        for alert in alerts:
            key = (alert.alert_type, alert.source_ip, alert.description)
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)

        return {
            "security_alerts": [asdict(a) for a in unique_alerts],
            "total_alerts": len(unique_alerts),
        }

    def analyze_tcp_sessions(self) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {}

        fields = [
            "tcp.stream",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "frame.len",
            "frame.time_relative",
            "tcp.payload",
            "_ws.col.protocol",
            "_ws.col.info",
        ]

        # Using defaultdict to aggregate stream data
        sessions = defaultdict(
            lambda: {
                "src": "",
                "dst": "",
                "sport": "",
                "dport": "",
                "packet_count": 0,
                "bytes": 0,
                "start_time": None,
                "end_time": None,
                "payload_hex": "",
                "protocols": Counter(),
                "summary": "",
            }
        )

        for row in tshark.stream_fields(
            str(self.filepath), fields, display_filter="tcp"
        ):
            stream_id = row.get("tcp.stream")
            if not stream_id:
                continue

            s = sessions[stream_id]
            # Capture first IP tuple seen in stream
            if not s["src"]:
                s["src"] = row.get("ip.src", "?")
                s["dst"] = row.get("ip.dst", "?")
                s["sport"] = row.get("tcp.srcport", "0")
                s["dport"] = row.get("tcp.dstport", "0")

            s["packet_count"] += 1
            pkt_len = int(row.get("frame.len", 0))
            s["bytes"] += pkt_len

            try:
                ts = float(row.get("frame.time_relative", 0))
                if s["start_time"] is None or ts < s["start_time"]:
                    s["start_time"] = ts
                if s["end_time"] is None or ts > s["end_time"]:
                    s["end_time"] = ts
            except ValueError:
                pass

            payload = row.get("tcp.payload")
            # Limit payload accumulation to 2KB per session for preview
            if payload and len(s["payload_hex"]) < 4000:
                s["payload_hex"] += payload.replace(":", "")

            proto = row.get("_ws.col.protocol")
            if proto:
                s["protocols"][proto] += 1

            info = row.get("_ws.col.info")
            if info and not s["summary"]:
                s["summary"] = info

        results = []
        for sid, data in sessions.items():
            payload_ascii = ""
            payload_hex_view = ""
            try:
                payload_bytes = bytes.fromhex(data["payload_hex"])
                # ASCII decode
                payload_ascii = payload_bytes.decode("utf-8", errors="replace")
                payload_ascii = "".join(
                    c if c.isprintable() or c in "\n\r\t" else "."
                    for c in payload_ascii
                )
                # Hex View (first 100 bytes)
                payload_hex_view = " ".join(f"{b:02x}" for b in payload_bytes[:100])
            except Exception:
                pass

            top_proto = (
                data["protocols"].most_common(1)[0][0] if data["protocols"] else "TCP"
            )

            results.append(
                TcpSession(
                    session_id=sid,
                    src_ip=data["src"],
                    src_port=int(data["sport"] or 0),
                    dst_ip=data["dst"],
                    dst_port=int(data["dport"] or 0),
                    packet_count=data["packet_count"],
                    byte_count=data["bytes"],
                    duration=round(
                        (data["end_time"] or 0) - (data["start_time"] or 0), 3
                    ),
                    start_time=data["start_time"] or 0,
                    payload_ascii=payload_ascii[:1000],
                    payload_hex=payload_hex_view,
                    protocol=top_proto,
                    summary=data["summary"],
                )
            )

        results.sort(key=lambda x: x.packet_count, reverse=True)

        return {
            "tcp_sessions": [
                asdict(s) for s in results[:50]
            ],  # Limit to top 50 sessions
            "total_sessions": len(results),
        }

    def analyze_details_tshark(self, display_filter: str = "http") -> Any:
        from .tshark import tshark

        if not tshark.is_available():
            return {"error": "Tshark not available. Please install Wireshark."}

        try:
            return tshark.run_json(str(self.filepath), display_filter=display_filter)
        except Exception as e:
            return {"error": str(e)}

    def get_packet_details(self, frame_number: int) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {"error": "Tshark not available"}

        try:
            packets = tshark.run_json(
                str(self.filepath), display_filter=f"frame.number == {frame_number}"
            )
            if packets:
                return packets[0]
            return {"error": "Packet not found"}
        except Exception as e:
            return {"error": str(e)}

    def get_tcp_stream_packets(
        self, stream_id: str, page: int = 1, page_size: int = 50
    ) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {"error": "Tshark not available"}

        fields = [
            "frame.number",
            "frame.time_relative",
            "frame.len",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.seq",
            "tcp.ack",
            "tcp.flags.str",
            "tcp.len",
            "_ws.col.info",
        ]

        packets = []
        skip = (page - 1) * page_size

        try:
            iterator = tshark.stream_fields(
                str(self.filepath), fields, display_filter=f"tcp.stream eq {stream_id}"
            )

            # Skip
            for _ in range(skip):
                next(iterator, None)

            # Take
            for _ in range(page_size):
                row = next(iterator, None)
                if row is None:
                    break
                packets.append(row)

        except Exception as e:
            return {"error": str(e)}

        return {"stream_id": stream_id, "page": page, "packets": packets}

    def analyze_tcp_anomalies(self, search_query: str | None = None) -> dict[str, Any]:
        from .tshark import tshark

        if not tshark.is_available():
            return {"error": "Tshark not available. Please install Wireshark."}

        # Simplified fields for list view (Lazy Loading Phase 1)
        fields = [
            "frame.number",
            "frame.time_relative",
            "frame.len",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "tcp.seq",
            "tcp.ack",
            "tcp.flags.str",
            "tcp.analysis.retransmission",
            "tcp.analysis.fast_retransmission",
            "tcp.analysis.out_of_order",
            "tcp.analysis.duplicate_ack",
            "tcp.analysis.zero_window",
            "tcp.analysis.window_full",
            "tcp.analysis.lost_segment",
            "tcp.analysis.ack_lost_segment",
            "tcp.flags.reset",
        ]

        # Filter for ANY tcp anomaly OR reset flag
        base_filter = "tcp.analysis.flags or tcp.flags.reset==1"
        display_filter = self._build_filter(base_filter, search_query)

        try:
            packets = tshark.run_json(
                str(self.filepath), display_filter=display_filter, fields=fields
            )
        except Exception as e:
            return {"error": f"Tshark analysis failed: {str(e)}"}

        # Aggregation Logic
        # stream_id -> { "src": ip, "dst": ip, "anomalies": { "retrans": 0, ... }, "packets": [] }
        streams = defaultdict(
            lambda: {
                "src_ip": "",
                "dst_ip": "",
                "src_port": "",
                "dst_port": "",
                "anomaly_counts": Counter(),
                "events": [],
            }
        )

        total_anomalies = Counter()

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            if not layers:
                continue

            stream_id = layers.get("tcp.stream", ["-1"])[0]
            if stream_id == "-1":
                continue

            # Basic info (taking from first packet or overwriting is fine for static flow)
            if not streams[stream_id]["src_ip"]:
                streams[stream_id]["src_ip"] = layers.get("ip.src", ["?"])[0]
                streams[stream_id]["dst_ip"] = layers.get("ip.dst", ["?"])[0]
                streams[stream_id]["src_port"] = layers.get("tcp.srcport", ["?"])[0]
                streams[stream_id]["dst_port"] = layers.get("tcp.dstport", ["?"])[0]

            # Check flags present in layers
            # Tshark fields are lists if present, or missing if not
            anomalies = []

            if "tcp.analysis.retransmission" in layers:
                anomalies.append("Retransmission")
                total_anomalies["Retransmission"] += 1
                streams[stream_id]["anomaly_counts"]["Retransmission"] += 1

            if "tcp.analysis.fast_retransmission" in layers:
                anomalies.append("Fast Retransmission")
                total_anomalies["Fast Retransmission"] += 1
                streams[stream_id]["anomaly_counts"]["Fast Retransmission"] += 1

            if "tcp.analysis.out_of_order" in layers:
                anomalies.append("Out-of-Order")
                total_anomalies["Out-of-Order"] += 1
                streams[stream_id]["anomaly_counts"]["Out-of-Order"] += 1

            if "tcp.analysis.duplicate_ack" in layers:
                anomalies.append("Duplicate ACK")
                total_anomalies["Duplicate ACK"] += 1
                streams[stream_id]["anomaly_counts"]["Duplicate ACK"] += 1

            if "tcp.analysis.zero_window" in layers:
                anomalies.append("Zero Window")
                total_anomalies["Zero Window"] += 1
                streams[stream_id]["anomaly_counts"]["Zero Window"] += 1

            if "tcp.analysis.window_full" in layers:
                anomalies.append("Window Full")
                total_anomalies["Window Full"] += 1
                streams[stream_id]["anomaly_counts"]["Window Full"] += 1

            if "tcp.analysis.lost_segment" in layers:
                anomalies.append("Lost Segment")
                total_anomalies["Lost Segment"] += 1
                streams[stream_id]["anomaly_counts"]["Lost Segment"] += 1

            if "tcp.analysis.ack_lost_segment" in layers:
                anomalies.append("ACK Lost")
                total_anomalies["ACK Lost"] += 1
                streams[stream_id]["anomaly_counts"]["ACK Lost"] += 1

            if "tcp.flags.reset" in layers and layers["tcp.flags.reset"][0] in (
                "1",
                "True",
            ):
                anomalies.append("Reset")
                total_anomalies["Reset"] += 1
                streams[stream_id]["anomaly_counts"]["Reset"] += 1

            if anomalies:
                streams[stream_id]["events"].append(
                    {
                        "frame": layers.get("frame.number", ["?"])[0],
                        "time": layers.get("frame.time_relative", ["0"])[0],
                        "len": layers.get("frame.len", ["0"])[0],
                        "types": anomalies,
                        "src": layers.get("ip.src", ["?"])[0],
                        "dst": layers.get("ip.dst", ["?"])[0],
                        "tcp": {
                            "seq": layers.get("tcp.seq", ["0"])[0],
                            "ack": layers.get("tcp.ack", ["0"])[0],
                            "win": layers.get("tcp.window_size_value", ["0"])[0],
                            "flags_str": layers.get("tcp.flags.str", [""])[0],
                            "flags_hex": layers.get("tcp.flags", ["0x00"])[0],
                        },
                    }
                )

        # Format result
        session_list = []
        for sid, data in streams.items():
            counts = data["anomaly_counts"]

            session_list.append(
                {
                    "stream_id": sid,
                    "src": f"{data['src_ip']}:{data['src_port']}",
                    "dst": f"{data['dst_ip']}:{data['dst_port']}",
                    "anomaly_summary": dict(counts),
                    "events_count": len(data["events"]),
                    "events": data["events"],
                }
            )

        # Filter out sessions with no events
        session_list = [s for s in session_list if s["events_count"] > 0]

        # Sort by total anomaly count desc
        session_list.sort(
            key=lambda x: sum(x["anomaly_summary"].values()), reverse=True
        )

        result = {
            "total_anomalies": dict(total_anomalies),
            "anomalous_sessions": session_list,
            "scan_time": str(Path(self.filepath).stat().st_mtime),
        }

        return result


def analyze_pcap(
    filepath: str, analysis_type: str = "pcap_summary", options: dict | None = None
) -> dict[str, Any]:
    analyzer = PcapAnalyzer(filepath)
    options = options or {}
    output_dir = options.get("output_dir")

    # Configure Tshark if provided
    tshark_path = options.get("tshark_path")
    if tshark_path:
        from .tshark import tshark

        tshark.set_path(tshark_path)

    result = None

    if analysis_type == "pcap_summary":
        result_obj = analyzer.analyze_summary()
        result = result_obj.to_dict()
    elif analysis_type == "http_analysis":
        result = analyzer.analyze_http()
    elif analysis_type == "dns_analysis":
        result = analyzer.analyze_dns()
    elif analysis_type == "tls_analysis":
        result = analyzer.analyze_tls()
    elif analysis_type == "security_scan":
        result = analyzer.analyze_security()
    elif analysis_type == "tcp_sessions":
        result = analyzer.analyze_tcp_sessions()
    elif analysis_type == "tshark_http":
        result = {"tshark_data": analyzer.analyze_details_tshark("http")}
    elif analysis_type == "tshark_tls":
        result = {"tshark_data": analyzer.analyze_details_tshark("tls")}
    elif analysis_type == "tcp_anomalies":
        result = analyzer.analyze_tcp_anomalies()
    else:
        raise ValueError(f"Unknown analysis type: {analysis_type}")

    if result:
        analyzer._save_report(result, analysis_type, output_dir)

    return result
