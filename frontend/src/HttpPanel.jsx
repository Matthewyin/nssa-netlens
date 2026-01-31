import { useState, useEffect } from 'react';
import './HttpPanel.css';
import PacketDetailTree from './PacketDetailTree';

function HttpPanel({ data, filePath }) {
  const [selectedReqIndex, setSelectedReqIndex] = useState(null);
  const [selectedPacketDetails, setSelectedPacketDetails] = useState(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);

  const requests = data?.requests || [];

  const handleReqClick = async (req, index) => {
    setSelectedReqIndex(index);
    setIsLoadingDetails(true);
    setSelectedPacketDetails(null);
    try {
      const details = await window.electronAPI.getPacketDetails(filePath, req.frame);
      setSelectedPacketDetails(details);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingDetails(false);
    }
  };
  
  const getHttpBody = (details) => {
      if (!details) return null;
      const http = details._source?.layers?.http;
      if (!http) return null;
      
      let body = http['http.file_data'] || http['http.file_data_text'] || http['json'];
      if (Array.isArray(body)) body = body[0];
      
      // JSON pretty print if possible
      if (typeof body === 'object') return JSON.stringify(body, null, 2);
      
      return body;
  };
  
  const selectedReq = selectedReqIndex !== null ? requests[selectedReqIndex] : null;
  const bodyContent = getHttpBody(selectedPacketDetails);

  if (requests.length === 0) {
      return <div className="empty-state">No HTTP requests found.</div>;
  }

  return (
    <div className="http-container">
      {/* Sidebar List */}
      <div className="http-sidebar">
        {requests.map((req, idx) => (
          <div 
            key={idx} 
            className={`http-item ${selectedReqIndex === idx ? 'active' : ''}`}
            onClick={() => handleReqClick(req, idx)}
          >
            <div className="http-row-1">
              {req.type === 'request' ? (
                  <span className={`http-method-badge method-${req.method?.toLowerCase()}`}>{req.method}</span>
              ) : (
                  <span className={`http-method-badge RESP`}>RESP</span>
              )}
              <span className={`http-status status-${String(req.status || '').charAt(0)}xx`}>
                  {req.status}
              </span>
            </div>
            <div className="http-row-2">
               {req.host}{req.path}
            </div>
          </div>
        ))}
      </div>

      {/* Content Area */}
      <div className="http-content">
        {selectedReq ? (
            <>
                <div className="http-detail-header">
                    <div className="http-detail-url">
                        {selectedReq.type === 'request' ? 
                            `${selectedReq.method} http://${selectedReq.host}${selectedReq.path}` : 
                            `Response ${selectedReq.status}`
                        }
                    </div>
                    <div className="http-detail-meta">
                        <span>Frame: #{selectedReq.frame}</span>
                        <span>Stream: {selectedReq.stream}</span>
                        {selectedReq.ua && <span>UA: {selectedReq.ua}</span>}
                        {selectedReq.ctype && <span>Type: {selectedReq.ctype}</span>}
                    </div>
                </div>

                {isLoadingDetails && <div className="http-loading">Loading details...</div>}
                
                {selectedPacketDetails && (
                    <>
                        {bodyContent && (
                            <>
                                <div className="http-section-title">Body Preview</div>
                                <div className="http-body-preview">{bodyContent}</div>
                            </>
                        )}
                        
                        <div className="http-section-title">Full Headers</div>
                        <PacketDetailTree 
                            data={selectedPacketDetails._source?.layers?.http} 
                            label="HTTP Protocol" 
                            initialExpanded={true} 
                        />
                    </>
                )}
            </>
        ) : (
            <div className="diag-placeholder">
                <h3>Select a request to view details</h3>
            </div>
        )}
      </div>
    </div>
  );
}

export default HttpPanel;
