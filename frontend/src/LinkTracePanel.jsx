import { useState } from 'react';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from 'react-resizable-panels';
import './LinkTracePanel.css';
import PacketDetailTree from './PacketDetailTree';

const PACKETS_PER_PAGE = 20;

const DEFAULT_COLUMNS = {
    seq: { label: '#', visible: true, required: true },
    relative_time_ms: { label: 'Time', visible: true, required: true },
    size: { label: 'Size', visible: true, required: true },
    flags: { label: 'Flags', visible: true, required: true },
    seq_num: { label: 'Seq', visible: true, required: true },
    ack_num: { label: 'Ack', visible: true, required: true },
    info: { label: 'Info', visible: true, required: true },
    frame_number: { label: 'Frame', visible: false, required: false },
    window_size: { label: 'Window', visible: false, required: false },
    checksum: { label: 'Checksum', visible: false, required: false },
    options: { label: 'Options', visible: false, required: false },
};

function ConfidenceBadge({ value }) {
    const level = value >= 0.9 ? 'high' : value >= 0.7 ? 'medium' : 'low';
    return (
        <span className={`confidence-badge ${level}`}>
            {Math.round(value * 100)}%
        </span>
    );
}

function MethodTag({ method }) {
    const display = method.replace(/_/g, ' ').replace('http header', 'HTTP');
    return <span className="method-tag">{display}</span>;
}

function PacketTable({ packets, totalPackets, onExportCSV, pcapFile, onPacketClick, selectedPacket }) {
    const [currentPage, setCurrentPage] = useState(1);
    const [columns, setColumns] = useState(DEFAULT_COLUMNS);
    const [showColumnSelector, setShowColumnSelector] = useState(false);

    if (!packets || packets.length === 0) {
        return <div className="no-packets">No packet data available</div>;
    }

    const totalPages = Math.ceil(packets.length / PACKETS_PER_PAGE);
    const startIdx = (currentPage - 1) * PACKETS_PER_PAGE;
    const endIdx = startIdx + PACKETS_PER_PAGE;
    const displayedPackets = packets.slice(startIdx, endIdx);

    const visibleColumns = Object.entries(columns).filter(([_, config]) => config.visible);

    const toggleColumn = (key) => {
        if (columns[key].required) return;
        setColumns(prev => ({
            ...prev,
            [key]: { ...prev[key], visible: !prev[key].visible }
        }));
    };

    const formatValue = (key, value) => {
        if (key === 'relative_time_ms') return `+${value.toFixed(2)}ms`;
        if (key === 'size') return `${value}B`;
        if (value === null || value === undefined) return '-';
        return String(value);
    };

    const handleExportCSV = () => {
        const headers = visibleColumns.map(([_, config]) => config.label);
        const rows = packets.map(pkt => 
            visibleColumns.map(([key, _]) => formatValue(key, pkt[key]))
        );
        const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'packets.csv';
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleOpenInWireshark = (e, frameNumber) => {
        e.stopPropagation(); // Prevent triggering row click
        if (window.electronAPI?.openInWireshark && pcapFile) {
            window.electronAPI.openInWireshark(pcapFile, frameNumber);
        }
    };

    return (
        <div className="packet-table-container">
            <div className="packet-table-toolbar">
                <div className="toolbar-left">
                    <span className="packet-count">
                        {packets.length} packets
                    </span>
                </div>
                <div className="toolbar-right">
                    <div className="column-selector-wrapper">
                        <button 
                            className="toolbar-btn"
                            onClick={() => setShowColumnSelector(!showColumnSelector)}
                        >
                            Columns ▼
                        </button>
                        {showColumnSelector && (
                            <div className="column-selector-dropdown">
                                {Object.entries(columns).map(([key, config]) => (
                                    <label key={key} className={config.required ? 'disabled' : ''}>
                                        <input
                                            type="checkbox"
                                            checked={config.visible}
                                            onChange={() => toggleColumn(key)}
                                            disabled={config.required}
                                        />
                                        {config.label}
                                    </label>
                                ))}
                            </div>
                        )}
                    </div>
                    <button className="toolbar-btn" onClick={handleExportCSV}>
                        Export CSV
                    </button>
                </div>
            </div>

            <div className="packet-table-scroll">
                <table className="packet-table">
                    <thead>
                        <tr>
                            {visibleColumns.map(([key, config]) => (
                                <th key={key}>{config.label}</th>
                            ))}
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {displayedPackets.map((pkt, idx) => (
                            <tr 
                                key={pkt.seq || idx} 
                                className={`${pkt.is_retransmission ? 'retransmission' : ''} ${selectedPacket && selectedPacket.frame_number === pkt.frame_number ? 'selected' : ''}`}
                                onClick={() => onPacketClick && onPacketClick(pkt)}
                            >
                                {visibleColumns.map(([key, _]) => (
                                    <td key={key} className={`col-${key}`}>
                                        {formatValue(key, pkt[key])}
                                    </td>
                                ))}
                                <td>
                                    <button 
                                        className="wireshark-btn"
                                        onClick={(e) => handleOpenInWireshark(e, pkt.frame_number)}
                                        title="Open in Wireshark"
                                    >
                                        🦈
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {totalPages > 1 && (
                <div className="pagination">
                    <span className="page-info">
                        {startIdx + 1}-{Math.min(endIdx, packets.length)} of {packets.length}
                    </span>
                    <div className="page-controls">
                        <button 
                            disabled={currentPage === 1}
                            onClick={() => setCurrentPage(1)}
                        >
                            «
                        </button>
                        <button 
                            disabled={currentPage === 1}
                            onClick={() => setCurrentPage(p => p - 1)}
                        >
                            ‹
                        </button>
                        <span className="page-number">{currentPage} / {totalPages}</span>
                        <button 
                            disabled={currentPage === totalPages}
                            onClick={() => setCurrentPage(p => p + 1)}
                        >
                            ›
                        </button>
                        <button 
                            disabled={currentPage === totalPages}
                            onClick={() => setCurrentPage(totalPages)}
                        >
                            »
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}

function HopCard({ hop, idx, isRequest, relativeTime, formatBytes, isExpanded, onToggle, pcapFile, onPacketClick, selectedPacket }) {
    return (
        <div className={`hop-wrapper ${hop.missing ? 'missing' : ''}`}>
            <div 
                className={`hop-card ${isRequest ? 'request' : 'response'} ${isExpanded ? 'expanded' : ''}`}
                onClick={onToggle}
            >
                <div className="hop-header">
                    <span className="hop-label">
                        {isRequest ? '→' : '←'} Hop {idx + 1}
                        {hop.packets?.length > 0 && (
                            <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                        )}
                    </span>
                    <span className={`hop-direction ${hop.direction}`}>
                        {isRequest ? 'REQ' : 'RSP'}
                    </span>
                </div>
                <div className="hop-session">Session #{hop.session_id}</div>
                <div className="hop-flow">
                    <span className="hop-src">{hop.src}</span>
                    <span className="hop-arrow">{isRequest ? '→' : '←'}</span>
                    <span className="hop-dst">{hop.dst}</span>
                </div>
                <div className="hop-stats">
                    {hop.missing ? (
                        <span className="missing-label">⚠️ Not captured</span>
                    ) : (
                        <>
                            <span>{hop.packet_count} pkts</span>
                            <span>{formatBytes(hop.byte_count || 0)}</span>
                            <span>+{relativeTime}ms</span>
                        </>
                    )}
                </div>
            </div>
            
            {isExpanded && hop.packets?.length > 0 && (
                <div className="hop-packets-panel">
                    <PacketTable 
                        packets={hop.packets} 
                        totalPackets={hop.total_packets || hop.packets.length}
                        pcapFile={pcapFile}
                        onPacketClick={onPacketClick}
                        selectedPacket={selectedPacket}
                    />
                </div>
            )}
        </div>
    );
}

function ChainVisualization({ chain, pcapFile, onPacketClick, selectedPacket }) {
    const [expandedHops, setExpandedHops] = useState({});

    if (!chain || !chain.hops || chain.hops.length === 0) {
        return <div className="chain-empty">Select a chain to view details</div>;
    }

    const formatBytes = (bytes) => {
        if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
        if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`;
        return `${bytes}B`;
    };

    const firstHopTime = chain.hops.find(h => h.start_time > 0)?.start_time || 0;

    const toggleHop = (idx) => {
        setExpandedHops(prev => ({ ...prev, [idx]: !prev[idx] }));
    };

    return (
        <div className="chain-viz">
            <div className="chain-header">
                <h4>Chain: {chain.chain_id}</h4>
                <div className="chain-meta">
                    <ConfidenceBadge value={chain.confidence} />
                    <MethodTag method={chain.method} />
                    <span className="latency-tag">Latency: {chain.latency_ms.toFixed(2)}ms</span>
                </div>
            </div>
            
            <div className="chain-flow">
                {chain.hops.map((hop, idx) => {
                    const isRequest = hop.direction === 'request';
                    const relativeTime = hop.start_time > 0 ? ((hop.start_time - firstHopTime) * 1000).toFixed(2) : '-';
                    
                    return (
                        <div key={idx}>
                            <HopCard
                                hop={hop}
                                idx={idx}
                                isRequest={isRequest}
                                relativeTime={relativeTime}
                                formatBytes={formatBytes}
                                isExpanded={expandedHops[idx]}
                                onToggle={() => toggleHop(idx)}
                                pcapFile={pcapFile}
                                onPacketClick={onPacketClick}
                                selectedPacket={selectedPacket}
                            />
                            {idx < chain.hops.length - 1 && !expandedHops[idx] && (
                                <div className="hop-connector">
                                    <div className="connector-line" />
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function ResizeHandle() {
    return (
        <PanelResizeHandle className="resize-handle">
            <div className="resize-handle-inner" />
        </PanelResizeHandle>
    );
}

function LinkTracePanel({ data, files }) {
    const [selectedChain, setSelectedChain] = useState(null);
    const [selectedPacket, setSelectedPacket] = useState(null);
    const [packetDetails, setPacketDetails] = useState(null);
    const [loadingDetails, setLoadingDetails] = useState(false);

    if (!data) return null;

    const { chains = [], unmatched_sessions = [], stats = {} } = data;
    const pcapFile = files?.[0] || '';

    const handlePacketClick = async (pkt) => {
        setSelectedPacket(pkt);
        setLoadingDetails(true);
        try {
            const details = await window.electronAPI.getPacketDetails(pcapFile, pkt.frame_number);
            setPacketDetails(details);
        } catch (e) {
            console.error("Failed to fetch packet details:", e);
        } finally {
            setLoadingDetails(false);
        }
    };

    const handleChainSelect = (chain) => {
        setSelectedChain(chain);
        setSelectedPacket(null);
        setPacketDetails(null);
    };

    return (
        <div className="link-trace-container">
            <div className="summary-card">
                <h3>链路追踪结果</h3>
                <div className="stats-grid">
                    <div className="stat">
                        <label>总会话</label>
                        <div className="value">{stats.total_sessions || 0}</div>
                    </div>
                    <div className="stat">
                        <label>关联链路</label>
                        <div className="value" style={{ color: 'var(--accent-green)' }}>
                            {stats.matched_chains || 0}
                        </div>
                    </div>
                    <div className="stat">
                        <label>已匹配会话</label>
                        <div className="value">{stats.matched_sessions || 0}</div>
                    </div>
                </div>
                {stats.methods_used && Object.keys(stats.methods_used).length > 0 && (
                    <div className="methods-summary">
                        <span className="methods-label">匹配方法:</span>
                        {Object.entries(stats.methods_used).map(([method, count]) => (
                            <span key={method} className="method-count">
                                {method}: {count}
                            </span>
                        ))}
                    </div>
                )}
            </div>

            <div className="link-trace-split">
                <PanelGroup direction="horizontal" style={{ flex: 1, height: '100%' }}>
                    <Panel defaultSize={33} minSize={20}>
                        <div className="chain-list-panel">
                            <div className="chain-list">
                                <div className="chain-list-header">
                                    <span>Chain ID</span>
                                    <span>Confidence</span>
                                    <span>Method</span>
                                    <span>Hops</span>
                                </div>
                                {chains.length === 0 ? (
                                    <div className="chain-empty-list">
                                        No correlated chains found
                                    </div>
                                ) : (
                                    chains.map((chain, idx) => (
                                        <div
                                            key={idx}
                                            className={`chain-row ${selectedChain === chain ? 'active' : ''}`}
                                            onClick={() => handleChainSelect(chain)}
                                        >
                                            <span className="chain-id">{chain.chain_id}</span>
                                            <span><ConfidenceBadge value={chain.confidence} /></span>
                                            <span><MethodTag method={chain.method} /></span>
                                            <span className="hop-count">{chain.hops?.length || 0}</span>
                                        </div>
                                    ))
                                )}
                                
                                {unmatched_sessions.length > 0 && (
                                    <>
                                        <div className="unmatched-header">
                                            Unmatched Sessions ({unmatched_sessions.length})
                                        </div>
                                        {unmatched_sessions.slice(0, 20).map((session, idx) => (
                                            <div key={`unmatched-${idx}`} className="unmatched-row">
                                                <span>#{session.session_id}</span>
                                                <span className="unmatched-flow">
                                                    {session.src} → {session.dst}
                                                </span>
                                                <span>{session.packets} pkts</span>
                                            </div>
                                        ))}
                                    </>
                                )}
                            </div>
                        </div>
                    </Panel>
                    
                    <ResizeHandle />
                    
                    <Panel defaultSize={34} minSize={20}>
                        <div className="chain-viz-panel">
                            {selectedChain ? (
                                <div className="chain-viz-container">
                                    <ChainVisualization 
                                        chain={selectedChain} 
                                        pcapFile={pcapFile} 
                                        onPacketClick={handlePacketClick}
                                        selectedPacket={selectedPacket}
                                    />
                                </div>
                            ) : (
                                <div className="chain-placeholder">
                                    <h3>Select a chain to view details</h3>
                                    <p>Click on a chain row to see the hop-by-hop flow visualization</p>
                                </div>
                            )}
                        </div>
                    </Panel>
                    
                    <ResizeHandle />
                    
                    <Panel defaultSize={33} minSize={20}>
                        <div className="packet-details-panel-wrapper">
                            <div className="packet-details-panel">
                                {selectedPacket ? (
                                    <>
                                        <div className="packet-detail-header">
                                            <span>Frame #{selectedPacket.frame_number} Details</span>
                                            <button 
                                                className="wireshark-btn"
                                                onClick={() => window.electronAPI?.openInWireshark(pcapFile, selectedPacket.frame_number)}
                                                title="Open in Wireshark"
                                            >
                                                Open in Wireshark 🦈
                                            </button>
                                        </div>
                                        <div className="packet-detail-content">
                                            {loadingDetails ? (
                                                <div style={{textAlign: 'center', color: 'var(--text-muted)'}}>
                                                    Loading packet details...
                                                </div>
                                            ) : (
                                                packetDetails && (
                                                    <PacketDetailTree 
                                                        data={packetDetails._source?.layers} 
                                                        label={`Frame #${selectedPacket.frame_number}`} 
                                                        initialExpanded={true} 
                                                    />
                                                )
                                            )}
                                        </div>
                                    </>
                                ) : (
                                    <div className="chain-placeholder">
                                        <h3>Packet Details</h3>
                                        <p>Select a packet from the chain to view full details</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </Panel>
                </PanelGroup>
            </div>
        </div>
    );
}

export default LinkTracePanel;