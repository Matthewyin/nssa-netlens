"""
Link Tracer - Multi-hop TCP Session Correlation

Correlates TCP sessions across NAT/Firewall/Load Balancer hops using:
- P0: Payload fingerprint matching (hash of first N bytes)
- P0: HTTP header matching (X-Request-ID, X-Forwarded-For, X-Correlation-ID)
- P1: Time window + packet size sequence matching
"""

from __future__ import annotations
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from .tshark import tshark


@dataclass
class PacketInfo:
    """Individual packet details within a hop"""

    seq: int
    frame_number: int
    time_epoch: float
    relative_time_ms: float
    size: int
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    flags: str
    window_size: int
    checksum: str
    urgent_pointer: int
    options: str
    info: str
    is_retransmission: bool = False


@dataclass
class SessionInfo:
    """TCP session metadata with bidirectional flow tracking"""

    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    payload_fingerprint: str = ""
    http_headers: dict = field(default_factory=dict)
    packet_sizes: list = field(default_factory=list)
    file_source: str = ""
    forward_start: float = 0.0
    forward_end: float = 0.0
    forward_packets: int = 0
    forward_bytes: int = 0
    backward_start: float = 0.0
    backward_end: float = 0.0
    backward_packets: int = 0
    backward_bytes: int = 0


@dataclass
class ChainHop:
    """A single unidirectional hop in a session chain"""

    session_id: str
    src: str
    dst: str
    packet_count: int
    byte_count: int
    duration: float
    file: str
    direction: str = "request"
    start_time: float = 0.0
    missing: bool = False
    packets: list = field(default_factory=list)
    total_packets: int = 0


@dataclass
class SessionChain:
    """A chain of correlated sessions"""

    chain_id: str
    confidence: float
    method: str
    hops: list[ChainHop] = field(default_factory=list)
    latency_ms: float = 0.0


class LinkTracer:
    """
    Correlates multi-hop TCP sessions within PCAP files.

    Supports:
    - Single file: Find related sessions within one capture (e.g., Client->F5->Server)
    - Multi file: Correlate sessions across two captures (e.g., source and dest captures)
    """

    # Fingerprint size (first N bytes of payload)
    FINGERPRINT_SIZE = 64
    # Time window for temporal correlation (seconds)
    TIME_WINDOW = 0.5
    # Minimum confidence threshold
    MIN_CONFIDENCE = 0.6

    def __init__(self):
        self.sessions: dict[str, SessionInfo] = {}
        self.chain_counter = 0

    def _extract_sessions(self, filepath: str, file_tag: str = "") -> list[SessionInfo]:
        """Extract TCP session metadata from PCAP file"""
        if not tshark.is_available():
            return []

        # First pass: Get session basics
        fields = [
            "tcp.stream",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "frame.time_epoch",
            "frame.len",
            "tcp.payload",
        ]

        sessions: dict[str, SessionInfo] = {}

        try:
            for row in tshark.stream_fields(filepath, fields, display_filter="tcp"):
                stream_id = row.get("tcp.stream")
                if not stream_id:
                    continue

                if stream_id not in sessions:
                    sessions[stream_id] = SessionInfo(
                        session_id=stream_id,
                        src_ip=row.get("ip.src", ""),
                        src_port=int(row.get("tcp.srcport", 0)),
                        dst_ip=row.get("ip.dst", ""),
                        dst_port=int(row.get("tcp.dstport", 0)),
                        file_source=file_tag or filepath.split("/")[-1],
                    )

                session = sessions[stream_id]
                session.packet_count += 1

                frame_len = int(row.get("frame.len", 0))
                session.byte_count += frame_len
                if len(session.packet_sizes) < 20:
                    session.packet_sizes.append(frame_len)

                try:
                    ts = float(row.get("frame.time_epoch", 0))
                    if session.start_time == 0 or ts < session.start_time:
                        session.start_time = ts
                    if ts > session.end_time:
                        session.end_time = ts

                    pkt_src_ip = row.get("ip.src", "")
                    is_forward = pkt_src_ip == session.src_ip

                    if is_forward:
                        session.forward_packets += 1
                        session.forward_bytes += frame_len
                        if session.forward_start == 0 or ts < session.forward_start:
                            session.forward_start = ts
                        if ts > session.forward_end:
                            session.forward_end = ts
                    else:
                        session.backward_packets += 1
                        session.backward_bytes += frame_len
                        if session.backward_start == 0 or ts < session.backward_start:
                            session.backward_start = ts
                        if ts > session.backward_end:
                            session.backward_end = ts
                except (ValueError, TypeError):
                    pass

                # Payload fingerprint (hash first N bytes of first packet with payload)
                if not session.payload_fingerprint:
                    payload_hex = row.get("tcp.payload", "")
                    if payload_hex:
                        try:
                            payload_bytes = bytes.fromhex(payload_hex.replace(":", ""))
                            if len(payload_bytes) >= 8:  # Minimum payload size
                                fingerprint_data = payload_bytes[
                                    : self.FINGERPRINT_SIZE
                                ]
                                session.payload_fingerprint = hashlib.md5(
                                    fingerprint_data
                                ).hexdigest()[:16]
                        except Exception:
                            pass

        except Exception as e:
            print(f"Error extracting sessions: {e}")

        # Second pass: Extract HTTP headers for correlation
        self._extract_http_headers(filepath, sessions)

        return list(sessions.values())

    def _extract_http_headers(
        self, filepath: str, sessions: dict[str, SessionInfo]
    ) -> None:
        """Extract HTTP correlation headers from sessions"""
        http_fields = [
            "tcp.stream",
            "http.request.line",
            "http.x_forwarded_for",
        ]

        # Custom headers we look for
        correlation_headers = [
            "x-request-id",
            "x-correlation-id",
            "x-trace-id",
            "x-forwarded-for",
            "x-real-ip",
        ]

        try:
            # Use raw packet data to find headers
            for row in tshark.stream_fields(
                filepath, http_fields + ["tcp.payload"], display_filter="http"
            ):
                stream_id = row.get("tcp.stream")
                if not stream_id or stream_id not in sessions:
                    continue

                session = sessions[stream_id]

                # Parse X-Forwarded-For
                xff = row.get("http.x_forwarded_for")
                if xff:
                    session.http_headers["x-forwarded-for"] = xff

                # Parse payload for other headers
                payload_hex = row.get("tcp.payload", "")
                if payload_hex:
                    try:
                        payload = bytes.fromhex(payload_hex.replace(":", "")).decode(
                            "utf-8", errors="ignore"
                        )
                        for header in correlation_headers:
                            pattern = rf"{header}:\s*([^\r\n]+)"
                            match = re.search(pattern, payload, re.IGNORECASE)
                            if match:
                                session.http_headers[header.lower()] = match.group(
                                    1
                                ).strip()
                    except Exception:
                        pass

        except Exception as e:
            print(f"Error extracting HTTP headers: {e}")

    def _parse_tcp_flags(self, flags_value: str) -> str:
        """Convert tshark tcp.flags hex value to readable string"""
        try:
            flags_int = (
                int(flags_value, 16)
                if flags_value.startswith("0x")
                else int(flags_value)
            )
            parts = []
            if flags_int & 0x02:
                parts.append("SYN")
            if flags_int & 0x10:
                parts.append("ACK")
            if flags_int & 0x08:
                parts.append("PSH")
            if flags_int & 0x01:
                parts.append("FIN")
            if flags_int & 0x04:
                parts.append("RST")
            if flags_int & 0x20:
                parts.append("URG")
            return ",".join(parts) if parts else "---"
        except (ValueError, TypeError):
            return flags_value or "---"

    def _extract_hop_packets(
        self,
        filepath: str,
        session_id: str,
        src_ip: str,
        direction: str,
    ) -> list[PacketInfo]:
        """Extract packet details for a specific hop (session + direction)"""
        if not tshark.is_available():
            return []

        fields = [
            "frame.number",
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.seq",
            "tcp.ack",
            "tcp.flags",
            "tcp.window_size_value",
            "tcp.checksum",
            "tcp.urgent_pointer",
            "tcp.options",
            "_ws.col.Info",
            "tcp.analysis.retransmission",
        ]

        packets: list[PacketInfo] = []
        first_time: float = 0.0
        seq_counter = 0

        try:
            display_filter = f"tcp.stream eq {session_id}"
            for row in tshark.stream_fields(
                filepath, fields, display_filter=display_filter
            ):
                pkt_src_ip = row.get("ip.src", "")
                is_forward = pkt_src_ip == src_ip

                if (direction == "request" and not is_forward) or (
                    direction == "response" and is_forward
                ):
                    continue

                seq_counter += 1
                time_epoch = float(row.get("frame.time_epoch", 0))
                if first_time == 0:
                    first_time = time_epoch

                pkt = PacketInfo(
                    seq=seq_counter,
                    frame_number=int(row.get("frame.number", 0)),
                    time_epoch=time_epoch,
                    relative_time_ms=round((time_epoch - first_time) * 1000, 3),
                    size=int(row.get("frame.len", 0)),
                    src_port=int(row.get("tcp.srcport", 0)),
                    dst_port=int(row.get("tcp.dstport", 0)),
                    seq_num=int(row.get("tcp.seq", 0)),
                    ack_num=int(row.get("tcp.ack", 0)),
                    flags=self._parse_tcp_flags(row.get("tcp.flags", "")),
                    window_size=int(row.get("tcp.window_size_value", 0)),
                    checksum=row.get("tcp.checksum", ""),
                    urgent_pointer=int(row.get("tcp.urgent_pointer", 0)),
                    options=row.get("tcp.options", ""),
                    info=row.get("_ws.col.Info", ""),
                    is_retransmission=row.get("tcp.analysis.retransmission", "") != "",
                )
                packets.append(pkt)
        except Exception as e:
            print(f"Error extracting hop packets: {e}")

        return packets

    def _match_by_payload_fingerprint(
        self, sessions: list[SessionInfo]
    ) -> list[tuple[SessionInfo, SessionInfo, float]]:
        """Match sessions by payload fingerprint with proxy pattern validation"""
        matches = []
        fingerprint_index: dict[str, list[SessionInfo]] = defaultdict(list)

        for session in sessions:
            if session.payload_fingerprint:
                fingerprint_index[session.payload_fingerprint].append(session)

        for fingerprint, group in fingerprint_index.items():
            if len(group) >= 2:
                group.sort(key=lambda s: s.start_time)
                for i in range(len(group) - 1):
                    for j in range(i + 1, len(group)):
                        s1, s2 = group[i], group[j]

                        if s1.src_ip == s2.src_ip and s1.dst_ip == s2.dst_ip:
                            continue

                        time_diff = abs(s2.start_time - s1.start_time)
                        if time_diff > self.TIME_WINDOW * 2:
                            continue

                        is_direct_proxy = s1.dst_ip == s2.src_ip
                        is_port_preserved = (
                            s1.src_port == s2.src_port and s1.src_ip != s2.src_ip
                        )
                        is_same_vip = s1.dst_ip == s2.dst_ip and s1.src_ip != s2.src_ip

                        if is_direct_proxy:
                            matches.append((s1, s2, 0.90))
                        elif is_port_preserved and is_same_vip:
                            matches.append((s1, s2, 0.85))
                        elif is_port_preserved or is_same_vip:
                            matches.append((s1, s2, 0.75))

        return matches

    def _match_by_http_headers(
        self, sessions: list[SessionInfo]
    ) -> list[tuple[SessionInfo, SessionInfo, float]]:
        """Match sessions by HTTP correlation headers"""
        matches = []

        # Index by each correlation header
        header_indices: dict[str, dict[str, list[SessionInfo]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for session in sessions:
            for header, value in session.http_headers.items():
                if value and header in [
                    "x-request-id",
                    "x-correlation-id",
                    "x-trace-id",
                ]:
                    header_indices[header][value].append(session)

        # Find matches
        for header, value_index in header_indices.items():
            for value, group in value_index.items():
                if len(group) >= 2:
                    group.sort(key=lambda s: s.start_time)
                    for i in range(len(group) - 1):
                        for j in range(i + 1, len(group)):
                            if group[i].session_id != group[j].session_id:
                                matches.append((group[i], group[j], 0.95))

        # Match by X-Forwarded-For (Client IP appears in downstream request)
        for session in sessions:
            xff = session.http_headers.get("x-forwarded-for", "")
            if xff:
                client_ips = [ip.strip() for ip in xff.split(",")]
                for other in sessions:
                    if other.session_id != session.session_id:
                        if other.src_ip in client_ips:
                            # Time check: other session should be slightly before this one
                            if (
                                abs(other.start_time - session.start_time)
                                < self.TIME_WINDOW
                            ):
                                matches.append((other, session, 0.90))

        return matches

    def _match_by_timing_and_size(
        self, sessions: list[SessionInfo]
    ) -> list[tuple[SessionInfo, SessionInfo, float]]:
        """Match sessions by timing proximity and packet size patterns"""
        matches = []

        # Sort by start time
        sorted_sessions = sorted(sessions, key=lambda s: s.start_time)

        for i, s1 in enumerate(sorted_sessions):
            for j in range(i + 1, len(sorted_sessions)):
                s2 = sorted_sessions[j]

                # Time window check
                time_diff = s2.start_time - s1.start_time
                if time_diff > self.TIME_WINDOW:
                    break  # No more candidates in time window

                if time_diff < 0.001:  # Too close, likely same session
                    continue

                # Skip if same endpoints
                if s1.src_ip == s2.src_ip and s1.dst_ip == s2.dst_ip:
                    continue

                # Check if IPs/ports suggest a valid proxy relationship
                # Scenario 1: Direct proxy chain (s1.dst_ip == s2.src_ip)
                # Scenario 2: F5/NAT SNAT pattern - source port preserved across hops
                #   e.g., Client:21238 -> VIP, then SNAT:21238 -> Backend
                # Scenario 3: Shared VIP - s1.dst_ip == s2.dst_ip (same destination VIP)
                #   with source port preserved (strong indicator of same flow)

                is_direct_proxy = s1.dst_ip == s2.src_ip

                # F5 SNAT typically preserves source port
                # If both sessions have same source port AND go to same VIP, likely related
                is_snat_pattern = (
                    s1.src_port == s2.src_port  # Same source port (SNAT preserved)
                    and s1.dst_ip == s2.dst_ip  # Same destination VIP
                    and s1.src_ip
                    != s2.src_ip  # Different source IPs (client vs SNAT IP)
                )

                # Relaxed SNAT: same source port, different source IPs,
                # and s2.src could be a known SNAT range
                is_port_preserved_proxy = (
                    s1.src_port == s2.src_port  # Source port preserved
                    and s1.src_ip != s2.src_ip  # Different sources
                    and (
                        s1.dst_ip == s2.dst_ip  # Same VIP
                        or s1.dst_ip == s2.src_ip  # Direct chain
                    )
                )

                is_proxy_pattern = (
                    is_direct_proxy or is_snat_pattern or is_port_preserved_proxy
                )

                if not is_proxy_pattern:
                    continue

                # Compare packet size sequences
                if s1.packet_sizes and s2.packet_sizes:
                    similarity = self._size_sequence_similarity(
                        s1.packet_sizes, s2.packet_sizes
                    )
                    if similarity > 0.6:
                        confidence = 0.5 + (
                            similarity * 0.3
                        )  # Base 0.5 + up to 0.3 for similarity
                        matches.append((s1, s2, confidence))

        return matches

    def _size_sequence_similarity(self, sizes1: list[int], sizes2: list[int]) -> float:
        """Calculate similarity between two packet size sequences"""
        if not sizes1 or not sizes2:
            return 0.0

        # Compare first N packets
        n = min(len(sizes1), len(sizes2), 10)
        if n < 3:
            return 0.0

        # Allow some tolerance for header modifications
        matches = 0
        for i in range(n):
            s1, s2 = sizes1[i], sizes2[i]
            # Allow 20% size difference or 100 bytes (header rewriting)
            if abs(s1 - s2) <= max(100, 0.2 * max(s1, s2)):
                matches += 1

        return matches / n

    def _is_valid_hop_pair(self, s1: SessionInfo, s2: SessionInfo) -> bool:
        """Validate that two sessions can be consecutive hops in a chain"""
        is_direct_proxy = s1.dst_ip == s2.src_ip
        is_port_preserved = s1.src_port == s2.src_port and s1.src_ip != s2.src_ip
        is_same_vip = s1.dst_ip == s2.dst_ip and s1.src_ip != s2.src_ip
        return (
            is_direct_proxy or (is_port_preserved and is_same_vip) or is_port_preserved
        )

    def _split_invalid_chains(
        self, group_keys: list[str], session_map: dict[str, SessionInfo]
    ) -> list[list[str]]:
        """Split a group into valid sub-chains based on hop connectivity"""
        if len(group_keys) <= 1:
            return [group_keys]

        sorted_keys = sorted(group_keys, key=lambda k: session_map[k].start_time)
        valid_chains: list[list[str]] = []
        current_chain: list[str] = [sorted_keys[0]]

        for i in range(1, len(sorted_keys)):
            prev_session = session_map[current_chain[-1]]
            curr_session = session_map[sorted_keys[i]]

            if self._is_valid_hop_pair(prev_session, curr_session):
                current_chain.append(sorted_keys[i])
            else:
                if len(current_chain) >= 2:
                    valid_chains.append(current_chain)
                current_chain = [sorted_keys[i]]

        if len(current_chain) >= 2:
            valid_chains.append(current_chain)

        return valid_chains

    def _build_chains(
        self,
        matches: list[tuple[SessionInfo, SessionInfo, float, str]],
        filepath: str = "",
        file_mapping: Optional[dict[str, str]] = None,
        include_packets: bool = True,
    ) -> list[SessionChain]:
        """Build session chains from pairwise matches"""
        if not matches:
            return []

        # Union-Find for grouping
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            if x not in parent:
                parent[x] = x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: str, y: str):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Group sessions
        session_map: dict[str, SessionInfo] = {}
        match_info: dict[tuple[str, str], tuple[float, str]] = {}

        for s1, s2, confidence, method in matches:
            key1 = f"{s1.file_source}:{s1.session_id}"
            key2 = f"{s2.file_source}:{s2.session_id}"
            session_map[key1] = s1
            session_map[key2] = s2
            union(key1, key2)
            match_info[(key1, key2)] = (confidence, method)

        # Build groups
        groups: dict[str, list[str]] = defaultdict(list)
        for key in session_map:
            groups[find(key)].append(key)

        # Create chains - split invalid groups into valid sub-chains
        chains = []
        for group_keys in groups.values():
            if len(group_keys) < 2:
                continue

            valid_sub_chains = self._split_invalid_chains(group_keys, session_map)

            for sorted_keys in valid_sub_chains:
                if len(sorted_keys) < 2:
                    continue

                total_conf = 0
                methods_used = []
                for i in range(len(sorted_keys) - 1):
                    k1, k2 = sorted_keys[i], sorted_keys[i + 1]
                    if (k1, k2) in match_info:
                        conf, method = match_info[(k1, k2)]
                    elif (k2, k1) in match_info:
                        conf, method = match_info[(k2, k1)]
                    else:
                        conf, method = 0.5, "inferred"
                    total_conf += conf
                    methods_used.append(method)

                avg_confidence = (
                    total_conf / (len(sorted_keys) - 1) if len(sorted_keys) > 1 else 0.5
                )
                primary_method = (
                    max(set(methods_used), key=methods_used.count)
                    if methods_used
                    else "unknown"
                )

                directional_hops: list[ChainHop] = []

                for key in sorted_keys:
                    s = session_map[key]
                    file_path_for_packets = (
                        filepath
                        if filepath
                        else (
                            file_mapping.get(s.file_source, "") if file_mapping else ""
                        )
                    )

                    forward_packets: list = []
                    if (
                        include_packets
                        and file_path_for_packets
                        and s.forward_packets > 0
                    ):
                        forward_packets = [
                            asdict(p)
                            for p in self._extract_hop_packets(
                                file_path_for_packets, s.session_id, s.src_ip, "request"
                            )
                        ]

                    forward_hop = ChainHop(
                        session_id=s.session_id,
                        src=f"{s.src_ip}:{s.src_port}",
                        dst=f"{s.dst_ip}:{s.dst_port}",
                        packet_count=s.forward_packets,
                        byte_count=s.forward_bytes,
                        duration=round(s.forward_end - s.forward_start, 3)
                        if s.forward_packets > 0
                        else 0.0,
                        file=s.file_source,
                        direction="request",
                        start_time=s.forward_start,
                        missing=s.forward_packets == 0,
                        packets=forward_packets,
                        total_packets=len(forward_packets),
                    )
                    directional_hops.append(forward_hop)

                    backward_packets: list = []
                    if (
                        include_packets
                        and file_path_for_packets
                        and s.backward_packets > 0
                    ):
                        backward_packets = [
                            asdict(p)
                            for p in self._extract_hop_packets(
                                file_path_for_packets,
                                s.session_id,
                                s.src_ip,
                                "response",
                            )
                        ]

                    backward_hop = ChainHop(
                        session_id=s.session_id,
                        src=f"{s.dst_ip}:{s.dst_port}",
                        dst=f"{s.src_ip}:{s.src_port}",
                        packet_count=s.backward_packets,
                        byte_count=s.backward_bytes,
                        duration=round(s.backward_end - s.backward_start, 3)
                        if s.backward_packets > 0
                        else 0.0,
                        file=s.file_source,
                        direction="response",
                        start_time=s.backward_start,
                        missing=s.backward_packets == 0,
                        packets=backward_packets,
                        total_packets=len(backward_packets),
                    )
                    directional_hops.append(backward_hop)

                directional_hops.sort(
                    key=lambda h: (h.start_time if h.start_time > 0 else float("inf"))
                )

                hops = directional_hops

                if len(sorted_keys) >= 2:
                    first_session = session_map[sorted_keys[0]]
                    last_session = session_map[sorted_keys[-1]]
                    first_time = first_session.forward_start or first_session.start_time
                    last_time = last_session.backward_end or last_session.end_time
                    latency_ms = (last_time - first_time) * 1000
                else:
                    latency_ms = 0

                self.chain_counter += 1
                chains.append(
                    SessionChain(
                        chain_id=f"chain_{self.chain_counter:03d}",
                        confidence=round(avg_confidence, 2),
                        method=primary_method,
                        hops=hops,
                        latency_ms=round(latency_ms, 2),
                    )
                )

        # Sort by confidence
        chains.sort(key=lambda c: c.confidence, reverse=True)
        return chains

    def trace_single_file(self, filepath: str) -> dict[str, Any]:
        """
        Correlate sessions within a single PCAP file.
        Finds multi-hop patterns like Client -> Proxy -> Server
        """
        self.chain_counter = 0
        sessions = self._extract_sessions(filepath, filepath.split("/")[-1])

        if not sessions:
            return {
                "chains": [],
                "unmatched_sessions": [],
                "stats": {"total_sessions": 0, "matched_chains": 0, "methods_used": {}},
            }

        # Run all matching strategies
        all_matches = []

        # P0: Payload fingerprint
        fp_matches = self._match_by_payload_fingerprint(sessions)
        for s1, s2, conf in fp_matches:
            all_matches.append((s1, s2, conf, "payload_fingerprint"))

        # P0: HTTP headers
        http_matches = self._match_by_http_headers(sessions)
        for s1, s2, conf in http_matches:
            all_matches.append((s1, s2, conf, f"http_header"))

        # P1: Timing + size
        timing_matches = self._match_by_timing_and_size(sessions)
        for s1, s2, conf in timing_matches:
            all_matches.append((s1, s2, conf, "timing_size"))

        # Deduplicate (keep highest confidence per pair)
        best_matches: dict[tuple[str, str], tuple] = {}
        for match in all_matches:
            s1, s2, conf, method = match
            key = tuple(sorted([s1.session_id, s2.session_id]))
            if key not in best_matches or conf > best_matches[key][2]:
                best_matches[key] = match

        # Build chains
        chains = self._build_chains(list(best_matches.values()), filepath=filepath)

        # Find unmatched sessions
        matched_ids = set()
        for chain in chains:
            for hop in chain.hops:
                matched_ids.add(hop.session_id)

        unmatched = [
            {
                "session_id": s.session_id,
                "src": f"{s.src_ip}:{s.src_port}",
                "dst": f"{s.dst_ip}:{s.dst_port}",
                "packets": s.packet_count,
            }
            for s in sessions
            if s.session_id not in matched_ids
        ]

        # Statistics
        method_counts: dict[str, int] = defaultdict(int)
        for chain in chains:
            method_counts[chain.method] += 1

        return {
            "chains": [asdict(c) for c in chains],
            "unmatched_sessions": unmatched[:50],  # Limit output
            "stats": {
                "total_sessions": len(sessions),
                "matched_chains": len(chains),
                "matched_sessions": len(matched_ids),
                "methods_used": dict(method_counts),
            },
        }

    def trace_multi_file(self, file1: str, file2: str) -> dict[str, Any]:
        """
        Correlate sessions across two PCAP files.
        Finds matching flows between source and destination captures.
        """
        self.chain_counter = 0

        sessions1 = self._extract_sessions(file1, "file1")
        sessions2 = self._extract_sessions(file2, "file2")

        all_sessions = sessions1 + sessions2

        if not all_sessions:
            return {
                "chains": [],
                "unmatched_sessions": [],
                "stats": {"total_sessions": 0, "matched_chains": 0, "methods_used": {}},
            }

        # Run matching (cross-file prioritized)
        all_matches = []

        # Cross-file matching
        for s1 in sessions1:
            for s2 in sessions2:
                # Payload fingerprint
                if (
                    s1.payload_fingerprint
                    and s1.payload_fingerprint == s2.payload_fingerprint
                ):
                    all_matches.append((s1, s2, 0.90, "payload_fingerprint"))

                # HTTP header matching
                for header in ["x-request-id", "x-correlation-id", "x-trace-id"]:
                    v1 = s1.http_headers.get(header)
                    v2 = s2.http_headers.get(header)
                    if v1 and v1 == v2:
                        all_matches.append((s1, s2, 0.95, f"http_header:{header}"))

                # Timing correlation
                time_diff = abs(s1.start_time - s2.start_time)
                if time_diff < self.TIME_WINDOW:
                    # Check size similarity
                    if s1.packet_sizes and s2.packet_sizes:
                        sim = self._size_sequence_similarity(
                            s1.packet_sizes, s2.packet_sizes
                        )
                        if sim > 0.5:
                            conf = 0.5 + (sim * 0.3)
                            all_matches.append((s1, s2, conf, "timing_size"))

        # Also run intra-file matching
        intra_matches = []
        for sessions, tag in [(sessions1, "file1"), (sessions2, "file2")]:
            fp = self._match_by_payload_fingerprint(sessions)
            for s1, s2, conf in fp:
                intra_matches.append((s1, s2, conf, "payload_fingerprint"))

            http = self._match_by_http_headers(sessions)
            for s1, s2, conf in http:
                intra_matches.append((s1, s2, conf, "http_header"))

        all_matches.extend(intra_matches)

        best_matches: dict[tuple[str, str], tuple] = {}
        for match in all_matches:
            s1, s2, conf, method = match
            key_list = sorted(
                [
                    f"{s1.file_source}:{s1.session_id}",
                    f"{s2.file_source}:{s2.session_id}",
                ]
            )
            key: tuple[str, str] = (key_list[0], key_list[1])
            if key not in best_matches or conf > best_matches[key][2]:
                best_matches[key] = match

        # Build chains with file mapping for multi-file support
        file_mapping = {"file1": file1, "file2": file2}
        chains = self._build_chains(
            list(best_matches.values()),
            filepath="",
            file_mapping=file_mapping,
            include_packets=True,
        )

        # Unmatched
        matched_ids = set()
        for chain in chains:
            for hop in chain.hops:
                matched_ids.add(f"{hop.file}:{hop.session_id}")

        unmatched = []
        for s in all_sessions:
            session_key = f"{s.file_source}:{s.session_id}"
            if session_key not in matched_ids:
                unmatched.append(
                    {
                        "session_id": s.session_id,
                        "src": f"{s.src_ip}:{s.src_port}",
                        "dst": f"{s.dst_ip}:{s.dst_port}",
                        "packets": s.packet_count,
                        "file": s.file_source,
                    }
                )

        # Stats
        method_counts: dict[str, int] = defaultdict(int)
        for chain in chains:
            method_counts[chain.method.split(":")[0]] += 1

        return {
            "chains": [asdict(c) for c in chains],
            "unmatched_sessions": unmatched[:50],
            "stats": {
                "total_sessions": len(all_sessions),
                "file1_sessions": len(sessions1),
                "file2_sessions": len(sessions2),
                "matched_chains": len(chains),
                "matched_sessions": len(matched_ids),
                "methods_used": dict(method_counts),
            },
        }
