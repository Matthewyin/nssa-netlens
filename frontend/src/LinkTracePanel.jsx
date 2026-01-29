import { useState } from 'react';
import './LinkTracePanel.css';

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

function ChainVisualization({ chain }) {
    if (!chain || !chain.hops || chain.hops.length === 0) {
        return <div className="chain-empty">Select a chain to view details</div>;
    }

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
                {chain.hops.map((hop, idx) => (
                    <div key={idx} className="hop-wrapper">
                        <div className="hop-card">
                            <div className="hop-header">
                                <span className="hop-label">Hop {idx + 1}</span>
                                <span className="hop-file">{hop.file}</span>
                            </div>
                            <div className="hop-session">Session #{hop.session_id}</div>
                            <div className="hop-flow">
                                <span className="hop-src">{hop.src}</span>
                                <span className="hop-arrow">→</span>
                                <span className="hop-dst">{hop.dst}</span>
                            </div>
                            <div className="hop-stats">
                                <span>{hop.packet_count} pkts</span>
                                <span>{hop.duration}s</span>
                            </div>
                        </div>
                        {idx < chain.hops.length - 1 && (
                            <div className="hop-connector">
                                <div className="connector-line" />
                                <div className="connector-label">NAT/Proxy</div>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

function LinkTracePanel({ data, files }) {
    const [selectedChain, setSelectedChain] = useState(null);

    if (!data) return null;

    const { chains = [], unmatched_sessions = [], stats = {} } = data;

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
                                onClick={() => setSelectedChain(chain)}
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

                <div className="chain-detail">
                    {selectedChain ? (
                        <ChainVisualization chain={selectedChain} />
                    ) : (
                        <div className="chain-placeholder">
                            <h3>Select a chain to view details</h3>
                            <p>Click on a chain row to see the hop-by-hop flow visualization</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default LinkTracePanel;
