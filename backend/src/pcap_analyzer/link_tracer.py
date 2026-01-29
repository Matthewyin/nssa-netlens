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
from typing import Any
from .tshark import tshark


@dataclass
class SessionInfo:
    """TCP session metadata"""

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


@dataclass
class ChainHop:
    """A single hop in a session chain"""

    session_id: str
    src: str
    dst: str
    packet_count: int
    duration: float
    file: str


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

                # Frame length for size sequence
                frame_len = int(row.get("frame.len", 0))
                session.byte_count += frame_len
                if len(session.packet_sizes) < 20:  # Keep first 20 packet sizes
                    session.packet_sizes.append(frame_len)

                # Timestamps
                try:
                    ts = float(row.get("frame.time_epoch", 0))
                    if session.start_time == 0 or ts < session.start_time:
                        session.start_time = ts
                    if ts > session.end_time:
                        session.end_time = ts
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

    def _match_by_payload_fingerprint(
        self, sessions: list[SessionInfo]
    ) -> list[tuple[SessionInfo, SessionInfo, float]]:
        """Match sessions by payload fingerprint"""
        matches = []
        fingerprint_index: dict[str, list[SessionInfo]] = defaultdict(list)

        for session in sessions:
            if session.payload_fingerprint:
                fingerprint_index[session.payload_fingerprint].append(session)

        # Find groups with matching fingerprints
        for fingerprint, group in fingerprint_index.items():
            if len(group) >= 2:
                # Sort by start time
                group.sort(key=lambda s: s.start_time)
                for i in range(len(group) - 1):
                    for j in range(i + 1, len(group)):
                        # Don't match sessions from same IP pair
                        if (
                            group[i].src_ip == group[j].src_ip
                            and group[i].dst_ip == group[j].dst_ip
                        ):
                            continue
                        matches.append((group[i], group[j], 0.85))

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

                # Check if IPs suggest proxying (s1.dst == s2.src or similar)
                is_proxy_pattern = (
                    s1.dst_ip == s2.src_ip  # Direct proxy
                    or s1.dst_port in [80, 443, 8080, 8443]
                    and s2.dst_port in [80, 443, 8080, 8443]  # Both HTTP
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

    def _build_chains(
        self, matches: list[tuple[SessionInfo, SessionInfo, float, str]]
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

        # Create chains
        chains = []
        for group_keys in groups.values():
            if len(group_keys) < 2:
                continue

            # Sort by start time
            sorted_keys = sorted(group_keys, key=lambda k: session_map[k].start_time)

            # Calculate chain confidence (average of match confidences)
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

            # Build hops
            hops = []
            for key in sorted_keys:
                s = session_map[key]
                hops.append(
                    ChainHop(
                        session_id=s.session_id,
                        src=f"{s.src_ip}:{s.src_port}",
                        dst=f"{s.dst_ip}:{s.dst_port}",
                        packet_count=s.packet_count,
                        duration=round(s.end_time - s.start_time, 3),
                        file=s.file_source,
                    )
                )

            # Calculate end-to-end latency
            if len(hops) >= 2:
                first_session = session_map[sorted_keys[0]]
                last_session = session_map[sorted_keys[-1]]
                latency_ms = (last_session.start_time - first_session.start_time) * 1000
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
        chains = self._build_chains(list(best_matches.values()))

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

        # Build chains
        chains = self._build_chains(list(best_matches.values()))

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
