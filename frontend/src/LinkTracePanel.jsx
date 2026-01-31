import { useState, useRef, useMemo, useCallback } from 'react';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from 'react-resizable-panels';
import './LinkTracePanel.css';
import PacketDetailTree from './PacketDetailTree';
import PacketTable from './components/PacketTable';
import CompactPageHeader from './components/CompactPageHeader';
import SearchBar from './SearchBar';

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

function HopCard({ hop, idx, isRequest, relativeTime, formatBytes, isExpanded, onToggle, pcapFile, onPacketClick, selectedPacket }) {
    return (
        <div className={`hop-wrapper ${hop.missing ? 'missing' : ''} ${isExpanded ? 'expanded' : ''}`}>
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

function LinkTracePanel({ data, files, onExport, searchQuery, setSearchQuery }) {
    const [selectedChain, setSelectedChain] = useState(null);
    const [selectedPacket, setSelectedPacket] = useState(null);
    const [packetDetails, setPacketDetails] = useState(null);
    const [loadingDetails, setLoadingDetails] = useState(false);

    if (!data) return null;

    const { chains = [], unmatched_sessions = [], stats = {} } = data;
    const pcapFile = files?.[0] || '';

    const filteredChains = useMemo(() => {
        if (!searchQuery) return chains;
        const lower = searchQuery.toLowerCase();
        return chains.filter(c => 
            c.chain_id.toLowerCase().includes(lower) ||
            c.method.toLowerCase().includes(lower)
        );
    }, [chains, searchQuery]);

    const handlePacketClick = useCallback(async (pkt) => {
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
    }, [pcapFile]);

    const handleChainSelect = useCallback((chain) => {
        setSelectedChain(chain);
        setSelectedPacket(null);
        setPacketDetails(null);
    }, []);

    const statsConfig = [
        { label: '总会话', value: stats.total_sessions || 0 },
        { label: '关联链路', value: stats.matched_chains || 0, colorClass: 'success' },
        { label: '已匹配会话', value: stats.matched_sessions || 0 }
    ];

    const methodsContent = stats.methods_used && Object.keys(stats.methods_used).length > 0 ? (
        <div style={{ display: 'flex', gap: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
            {Object.entries(stats.methods_used).map(([method, count]) => (
                <span key={method} style={{ background: 'var(--bg-tertiary)', padding: '2px 6px', borderRadius: '4px' }}>
                    {method}: {count}
                </span>
            ))}
        </div>
    ) : null;

    const headerExtraContent = (
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {methodsContent}
            <div className="search-container">
                <SearchBar value={searchQuery} onChange={setSearchQuery} placeholder="Filter chains..." />
            </div>
        </div>
    );

    return (
        <div className="link-trace-container">
            <CompactPageHeader
                title="链路追踪结果"
                fileName={pcapFile?.split('/').pop()}
                stats={statsConfig}
                onExport={onExport}
                extraContent={headerExtraContent}
            />

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
                                {filteredChains.length === 0 ? (
                                    <div className="chain-empty-list">
                                        No matching chains found
                                    </div>
                                ) : (
                                    filteredChains.map((chain, idx) => (
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
                                                <div className="loading-details">
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