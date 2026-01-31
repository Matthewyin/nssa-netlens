import { useState } from 'react';
import './TlsPanel.css';
import PacketDetailTree from './PacketDetailTree';

function TlsPanel({ data, filePath }) {
  const [selectedHsIndex, setSelectedHsIndex] = useState(null);
  const [selectedPacketDetails, setSelectedPacketDetails] = useState(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);

  const handshakes = data?.handshakes || [];

  const handleHsClick = async (hs, index) => {
    setSelectedHsIndex(index);
    setIsLoadingDetails(true);
    setSelectedPacketDetails(null);
    try {
      const details = await window.electronAPI.getPacketDetails(filePath, hs.frame);
      setSelectedPacketDetails(details);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  const selectedHs = selectedHsIndex !== null ? handshakes[selectedHsIndex] : null;

  if (handshakes.length === 0) return <div className="empty-state">No TLS handshakes found.</div>;

  return (
    <div className="tls-container">
      <div className="tls-sidebar">
        {handshakes.map((hs, idx) => (
          <div 
            key={idx} 
            className={`tls-item ${selectedHsIndex === idx ? 'active' : ''}`}
            onClick={() => handleHsClick(hs, idx)}
          >
            <div className="tls-sni">{hs.sni || '(No SNI)'}</div>
            <div className="tls-meta">
                <span className="tls-version-badge">{hs.version}</span>
                {hs.type === 'ServerHello' ? (
                    <span className="tls-cipher">{hs.cipher || 'Unknown Cipher'}</span>
                ) : (
                    <span className="tls-cipher text-small">{hs.type}</span>
                )}
            </div>
          </div>
        ))}
      </div>

      <div className="tls-content">
        {selectedHs ? (
            <>
                <div className="tls-detail-header">
                    <div className="tls-detail-title">
                        TLS Handshake: {selectedHs.type}
                    </div>
                </div>

                {isLoadingDetails && <div className="tls-loading">Loading details...</div>}
                
                {selectedPacketDetails && (
                    <PacketDetailTree 
                        data={selectedPacketDetails._source?.layers} 
                        label="Packet Layers" 
                        initialExpanded={true} 
                    />
                )}
            </>
        ) : (
            <div className="diag-placeholder"><h3>Select a handshake</h3></div>
        )}
      </div>
    </div>
  );
}
export default TlsPanel;
