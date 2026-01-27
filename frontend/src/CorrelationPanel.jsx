import { useState } from 'react';
import './CorrelationPanel.css';
import PacketDetailTree from './PacketDetailTree';

function CorrelationPanel({ data, files }) {
    const [selectedMatch, setSelectedMatch] = useState(null);
    const [detailA, setDetailA] = useState(null);
    const [detailB, setDetailB] = useState(null);
    const [loadingDetails, setLoadingDetails] = useState(false);

    if (!data) return null;

    const handleRowClick = async (match) => {
        setSelectedMatch(match);
        setLoadingDetails(true);
        setDetailA(null);
        setDetailB(null);
        
        try {
            const pA = window.electronAPI.getPacketDetails(files[0], match.frame_a);
            const pB = match.frame_b ? window.electronAPI.getPacketDetails(files[1], match.frame_b) : Promise.resolve(null);
            
            const [resA, resB] = await Promise.all([pA, pB]);
            setDetailA(resA);
            setDetailB(resB);
        } catch (e) {
            console.error(e);
        } finally {
            setLoadingDetails(false);
        }
    };
    
    return (
        <div className="corr-container">
            <div className="summary-card">
                <h3>关联结果</h3>
                <div className="stats-grid">
                    <div className="stat">
                         <label>总匹配</label>
                         <div className="value">{data.matches?.length || 0}</div>
                    </div>
                    <div className="stat">
                         <label>丢包 (A-&gt;B)</label>
                         <div className="value" style={{color: '#ef4444'}}>{data.lost_in_b_count || 0}</div>
                    </div>
                    <div className="stat">
                         <label>时间偏移</label>
                         <div className="value">{(data.estimated_time_offset || 0).toFixed(6)}s</div>
                    </div>
                </div>
            </div>
            
            <div className="corr-split-view" style={{display: 'flex', flex: 1, overflow: 'hidden', marginTop: '20px', border: '1px solid var(--border-color)', borderRadius: '8px', background: 'var(--bg-card)'}}>
                <div className="corr-list" style={{width: '450px', overflowY: 'auto', borderRight: '1px solid var(--border-color)', marginTop: 0, borderRadius: 0, border: 'none', background: 'var(--bg-secondary)'}}>
                    <div className="corr-header" style={{position: 'sticky', top: 0, zIndex: 10}}>
                        <span>File A</span>
                        <span>Status</span>
                        <span>File B</span>
                        <span>Lat</span>
                    </div>
                    {data.matches?.slice(0, 100).map((m, idx) => (
                        <div 
                            key={idx} 
                            className={`corr-row ${selectedMatch === m ? 'active' : ''}`}
                            onClick={() => handleRowClick(m)}
                            style={{cursor: 'pointer', background: selectedMatch === m ? 'var(--bg-tertiary)' : ''}}
                        >
                            <span>#{m.frame_a}</span>
                            <span className="corr-status match">↔</span>
                            <span>#{m.frame_b}</span>
                            <span className="corr-latency">+{ (m.latency || 0).toFixed(3)}s</span>
                        </div>
                    ))}
                    {data.lost_frames_a?.map((f, idx) => (
                        <div 
                            key={'lost'+idx} 
                            className="corr-row lost"
                            onClick={() => handleRowClick({ frame_a: f, frame_b: null })}
                            style={{cursor: 'pointer'}}
                        >
                             <span>#{f}</span>
                             <span className="corr-status lost">×</span>
                             <span>MISSING</span>
                             <span>-</span>
                        </div>
                    ))}
                </div>
                
                <div className="corr-details" style={{flex: 1, padding: '20px', overflowY: 'auto', background: 'var(--bg-primary)'}}>
                     {selectedMatch ? (
                         <div style={{display: 'flex', gap: '20px', height: '100%'}}>
                             <div style={{flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column'}}>
                                 <h4 style={{marginBottom: '10px', color: 'var(--text-primary)'}}>File A: Frame #{selectedMatch.frame_a}</h4>
                                 <div style={{flex: 1, overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px', background: 'var(--bg-tertiary)'}}>
                                     {detailA ? (
                                         <PacketDetailTree data={detailA._source?.layers} label="Packet A" initialExpanded={true} />
                                     ) : (
                                         <div>Loading...</div>
                                     )}
                                 </div>
                             </div>
                             
                             <div style={{flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column'}}>
                                 <h4 style={{marginBottom: '10px', color: 'var(--text-primary)'}}>File B: {selectedMatch.frame_b ? `Frame #${selectedMatch.frame_b}` : 'MISSING'}</h4>
                                 <div style={{flex: 1, overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px', background: 'var(--bg-tertiary)'}}>
                                     {selectedMatch.frame_b ? (
                                         detailB ? (
                                            <PacketDetailTree data={detailB._source?.layers} label="Packet B" initialExpanded={true} />
                                         ) : (
                                            <div>Loading...</div>
                                         )
                                     ) : (
                                         <div style={{color: '#ef4444', fontWeight: 'bold'}}>Packet missing in File B</div>
                                     )}
                                 </div>
                             </div>
                         </div>
                     ) : (
                         <div className="diag-placeholder">
                             <h3>Select a match row to compare details</h3>
                         </div>
                     )}
                </div>
            </div>
        </div>
    );
}

export default CorrelationPanel;
