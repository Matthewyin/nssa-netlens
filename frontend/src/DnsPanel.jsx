import { useState } from 'react';
import './DnsPanel.css';
import PacketDetailTree from './PacketDetailTree';

function DnsPanel({ data, filePath }) {
  const [selectedQueryIndex, setSelectedQueryIndex] = useState(null);
  const [selectedPacketDetails, setSelectedPacketDetails] = useState(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);

  const queries = data?.queries || [];

  const handleQueryClick = async (query, index) => {
    setSelectedQueryIndex(index);
    setIsLoadingDetails(true);
    setSelectedPacketDetails(null);
    try {
      const details = await window.electronAPI.getPacketDetails(filePath, query.frame);
      setSelectedPacketDetails(details);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  const selectedQuery = selectedQueryIndex !== null ? queries[selectedQueryIndex] : null;

  if (queries.length === 0) {
      return <div className="empty-state">No DNS queries found.</div>;
  }

  return (
    <div className="dns-container">
      <div className="dns-sidebar">
        {queries.map((q, idx) => (
          <div 
            key={idx} 
            className={`dns-item ${selectedQueryIndex === idx ? 'active' : ''}`}
            onClick={() => handleQueryClick(q, idx)}
          >
            <span className="dns-type-badge">{q.type}</span>
            <div className="dns-domain">{q.domain}</div>
            {q.rcode && q.rcode !== "0" && (
                <span className="dns-status status-error">ERR</span>
            )}
          </div>
        ))}
      </div>

      <div className="dns-content">
        {selectedQuery ? (
            <>
                <div className="dns-detail-header">
                    <div className="dns-detail-title">
                        {selectedQuery.domain} ({selectedQuery.type})
                    </div>
                    <div className="dns-detail-meta">
                        <span>Frame: #{selectedQuery.frame}</span>
                        <span>ID: {selectedQuery.id}</span>
                        <span>{selectedQuery.is_response ? "Response" : "Query"}</span>
                    </div>
                </div>

                {isLoadingDetails && <div style={{color: '#94a3b8'}}>Loading details...</div>}
                
                {selectedPacketDetails && (
                    <>
                        <div className="dns-section-title">Full DNS Record</div>
                        <PacketDetailTree 
                            data={selectedPacketDetails._source?.layers?.dns} 
                            label="DNS Protocol" 
                            initialExpanded={true} 
                        />
                    </>
                )}
            </>
        ) : (
            <div className="diag-placeholder">
                <h3>Select a DNS query to view details</h3>
            </div>
        )}
      </div>
    </div>
  );
}

export default DnsPanel;
