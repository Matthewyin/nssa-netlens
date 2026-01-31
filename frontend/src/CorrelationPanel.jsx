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
            <div className="corr-split-view">
                <div className="corr-list">
                    <div className="corr-header">
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
                        >
                             <span>#{f}</span>
                             <span className="corr-status lost">×</span>
                             <span>MISSING</span>
                             <span>-</span>
                        </div>
                    ))}
                </div>
                
                <div className="corr-details">
                     {selectedMatch ? (
                         <div className="corr-compare-grid">
                             <div className="corr-compare-col">
                                 <h4>File A: Frame #{selectedMatch.frame_a}</h4>
                                 <div className="corr-compare-content">
                                     {detailA ? (
                                         <PacketDetailTree data={detailA._source?.layers} label="Packet A" initialExpanded={true} />
                                     ) : (
                                         <div>Loading...</div>
                                     )}
                                 </div>
                             </div>
                             
                             <div className="corr-compare-col">
                                 <h4>File B: {selectedMatch.frame_b ? `Frame #${selectedMatch.frame_b}` : 'MISSING'}</h4>
                                 <div className="corr-compare-content">
                                     {selectedMatch.frame_b ? (
                                         detailB ? (
                                            <PacketDetailTree data={detailB._source?.layers} label="Packet B" initialExpanded={true} />
                                         ) : (
                                            <div>Loading...</div>
                                         )
                                     ) : (
                                         <div className="corr-missing-text">Packet missing in File B</div>
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
