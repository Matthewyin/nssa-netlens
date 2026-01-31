import { useState, useEffect } from 'react';
import './DiagnosticsPanel.css';
import SequenceDiagram from './SequenceDiagram';
import PacketDetailTree from './PacketDetailTree';

function DiagnosticsPanel({ data, filePath }) {
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [selectedPacketDetails, setSelectedPacketDetails] = useState(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);

  // Select first session by default
  useEffect(() => {
    if (data?.anomalous_sessions?.length > 0 && !selectedSessionId) {
      setSelectedSessionId(data.anomalous_sessions[0].stream_id);
    }
  }, [data, selectedSessionId]);

  const selectedSession = data?.anomalous_sessions?.find(s => s.stream_id === selectedSessionId);

  const handleSessionClick = (id) => {
    setSelectedSessionId(id);
    setSelectedPacketDetails(null); // Clear details when switching session
  };

  const handlePacketClick = async (evt) => {
    setIsLoadingDetails(true);
    try {
      const details = await window.electronAPI.getPacketDetails(filePath, evt.frame);
      setSelectedPacketDetails(details);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  if (!data?.anomalous_sessions || data.anomalous_sessions.length === 0) {
    return (
      <div className="empty-state">
        <p>✅ 网络健康状况良好，未检测到 TCP 异常。</p>
      </div>
    );
  }

  return (
    <div className="diag-container">
      {/* Left Sidebar: Session List */}
      <div className="diag-sidebar">
        {data.anomalous_sessions.map((session) => (
          <div 
            key={session.stream_id} 
            className={`diag-item ${selectedSessionId === session.stream_id ? 'active' : ''}`}
            onClick={() => handleSessionClick(session.stream_id)}
          >
            <div className="diag-talker">
              <span>{session.src}</span>
              <span className="diag-arrow">↓</span>
              <span>{session.dst}</span>
            </div>
            
            <div className="diag-meta">
              <span className="alert-badge badge-medium">{session.events_count} Events</span>
              <span className="diag-issue-count">
                {Object.values(session.anomaly_summary).reduce((a, b) => a + b, 0)} Issues
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Right Content: Detail View */}
      <div className="diag-content">
        {selectedSession ? (
          <>
            <div className="diag-flow-panel">
                <div className="diag-detail-header">
                  <div className="diag-detail-title">
                    Session #{selectedSession.stream_id}: {selectedSession.src} ↔ {selectedSession.dst}
                  </div>
                </div>

                <SequenceDiagram 
                  events={selectedSession.events} 
                  clientIp={selectedSession.src.split(':')[0]} 
                  serverIp={selectedSession.dst.split(':')[0]} 
                  onPacketClick={handlePacketClick}
                />
            </div>

            <div className="diag-detail-panel">
                {isLoadingDetails && (
                  <div className="diag-loading">Loading packet details...</div>
                )}

                {selectedPacketDetails ? (
                  <div>
                    <h4 className="diag-pkt-title">
                      Packet Details (Frame #{selectedPacketDetails._source?.layers?.frame?.['frame.number']})
                    </h4>
                    <PacketDetailTree 
                      data={selectedPacketDetails._source?.layers} 
                      label="Packet Layers" 
                      initialExpanded={true} 
                    />
                  </div>
                ) : (
                  <div className="diag-empty-hint">
                    Click an arrow in the diagram to view details
                  </div>
                )}
            </div>
          </>
        ) : (
          <div className="diag-placeholder">
            <h3>Select a session to view details</h3>
            <p>Click on an item in the list to analyze the packet flow.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default DiagnosticsPanel;
