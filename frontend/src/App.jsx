import { useState, useEffect } from 'react';
import './App.css';
import SettingsModal from './SettingsModal';
import DiagnosticsPanel from './DiagnosticsPanel';
import HttpPanel from './HttpPanel';
import DnsPanel from './DnsPanel';
import TlsPanel from './TlsPanel';
import CorrelationPanel from './CorrelationPanel';
import LinkTracePanel from './LinkTracePanel';
import SearchBar from './SearchBar';
import AiChatSidebar from './AiChatSidebar';
import PacketDetailTree from './PacketDetailTree';
import logo from './assets/icon.svg';

const ANALYSIS_TYPES = [
  { id: 'pcap_summary', label: '概览分析', icon: '📊' },
  { id: 'http_analysis', label: 'HTTP 分析', icon: '🌐' },
  { id: 'dns_analysis', label: 'DNS 分析', icon: '🔍' },
  { id: 'tls_analysis', label: 'TLS 分析', icon: '🔒' },
  { id: 'tcp_sessions', label: 'TCP 会话', icon: '🔌' },
  { id: 'tcp_anomalies', label: '故障诊断', icon: '🚑' },
  { id: 'security_scan', label: '安全分析', icon: '🛡️' },
  { id: 'correlation', label: '对比分析', icon: '🔗' },
  { id: 'link_trace', label: '链路追踪', icon: '🔀' },
];

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

const CHART_COLORS = [
  '#3B82F6', '#22C55E', '#F97316', '#EF4444', '#8B5CF6',
  '#06B6D4', '#EC4899', '#F59E0B', '#10B981', '#6366F1'
];

function PieChart({ data, total }) {
  if (!data || data.length === 0) return null;
  
  let currentAngle = 0;
  const paths = data.slice(0, 8).map((item, idx) => {
    const percentage = total > 0 ? (item.count / total) * 100 : 0;
    const angle = (percentage / 100) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + angle;
    currentAngle = endAngle;
    
    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (endAngle - 90) * (Math.PI / 180);
    
    const x1 = 50 + 40 * Math.cos(startRad);
    const y1 = 50 + 40 * Math.sin(startRad);
    const x2 = 50 + 40 * Math.cos(endRad);
    const y2 = 50 + 40 * Math.sin(endRad);
    
    const largeArc = angle > 180 ? 1 : 0;
    
    const d = angle >= 359.9
      ? `M 50 10 A 40 40 0 1 1 49.99 10 Z`
      : `M 50 50 L ${x1} ${y1} A 40 40 0 ${largeArc} 1 ${x2} ${y2} Z`;
    
    return (
      <path
        key={idx}
        d={d}
        fill={CHART_COLORS[idx % CHART_COLORS.length]}
        stroke="#fff"
        strokeWidth="1"
      />
    );
  });

  return (
    <div className="pie-chart-container">
      <svg viewBox="0 0 100 100" className="pie-chart">
        {paths}
      </svg>
      <div className="pie-legend">
        {data.slice(0, 8).map((item, idx) => (
          <div key={idx} className="legend-item">
            <span 
              className="legend-color" 
              style={{ backgroundColor: CHART_COLORS[idx % CHART_COLORS.length] }}
            />
            <span className="legend-label">{item.name}</span>
            <span className="legend-value">{item.percentage}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrafficTimeline({ data }) {
  if (!data || !data.timeline || data.timeline.length === 0) return null;
  
  const maxBytes = Math.max(...data.timeline.map(t => t.bytes));
  
  return (
    <div className="timeline-container">
      <div className="timeline-chart">
        {data.timeline.map((point, idx) => (
          <div key={idx} className="timeline-bar-wrapper">
            <div 
              className="timeline-bar"
              style={{ 
                height: `${maxBytes > 0 ? (point.bytes / maxBytes) * 100 : 0}%`
              }}
              title={`${formatBytes(point.bytes)}`}
            />
          </div>
        ))}
      </div>
      <div className="timeline-labels">
        <span>{data.timeline[0]?.time || '0s'}</span>
        <span>{data.timeline[data.timeline.length - 1]?.time || ''}</span>
      </div>
    </div>
  );
}

function TcpSessionCard({ session, filePath }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [packetList, setPacketList] = useState([]);
  const [page, setPage] = useState(1);
  const [loadingList, setLoadingList] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packetDetails, setPacketDetails] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadPackets = async (pageNum) => {
    setLoadingList(true);
    try {
      const res = await window.electronAPI.getTcpStreamPackets(filePath, session.session_id, pageNum);
      if (res && res.packets) {
        setPacketList(res.packets);
        setPage(pageNum);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingList(false);
    }
  };

  const toggleExpand = () => {
    if (!isExpanded && packetList.length === 0) {
      loadPackets(1);
    }
    setIsExpanded(!isExpanded);
  };

  const handlePacketClick = async (pkt) => {
    setSelectedPacket(pkt);
    setLoadingDetail(true);
    try {
      const details = await window.electronAPI.getPacketDetails(filePath, pkt['frame.number']);
      setPacketDetails(details);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDetail(false);
    }
  };

  return (
    <div className="session-card" style={{padding: 0, overflow: 'hidden'}}>
      <div 
        className="session-header" 
        onClick={toggleExpand} 
        style={{padding: '16px', cursor: 'pointer', background: isExpanded ? 'var(--bg-tertiary)' : 'transparent', borderBottom: isExpanded ? '1px solid var(--border-color)' : 'none'}}
      >
        <div className="session-title">
          <span className="proto-tag" style={{background: '#3b82f6', color: 'white', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 'bold', marginRight: '8px'}}>
            {session.protocol || 'TCP'}
          </span>
          <span className="talker-ip">{session.src_ip}:{session.src_port}</span>
          <span className="session-arrow">↔</span>
          <span className="talker-ip">{session.dst_ip}:{session.dst_port}</span>
        </div>
        <div className="session-meta">
          <span>{session.packet_count} Pkts</span>
          <span className="meta-sep">·</span>
          <span>{formatBytes(session.byte_count)}</span>
          <span className="meta-sep">·</span>
          <span>{session.duration}s</span>
          <span style={{marginLeft: 'auto', display: 'inline-block', transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s'}}>▼</span>
        </div>
      </div>
      
      {isExpanded && (
        <div className="session-stream-view" style={{display: 'flex', flexDirection: 'column', height: '500px'}}>
             <div className="stream-list" style={{flex: 1, overflowY: 'auto', padding: '10px'}}>
                 {loadingList ? <div style={{textAlign:'center', color:'var(--text-muted)'}}>Loading packets...</div> : (
                     packetList.map((pkt, idx) => {
                         const isOutgoing = pkt['ip.src'] === session.src_ip;
                         return (
                             <div key={idx} className={`flow-row ${isOutgoing ? 'right' : 'left'}`}>
                                 {!isOutgoing && <span className="flow-time">{parseFloat(pkt['frame.time_relative']).toFixed(3)}s</span>}
                                 
                                 <div 
                                     className={`flow-card ${isOutgoing ? 'right' : 'left'}`}
                                     onClick={() => handlePacketClick(pkt)}
                                     style={{border: selectedPacket === pkt ? '2px solid var(--accent-blue)' : ''}}
                                 >
                                     <div className="flow-meta">
                                         <span>Seq={pkt['tcp.seq']} Ack={pkt['tcp.ack']}</span>
                                         <span>Len: {pkt['frame.len']}</span>
                                     </div>
                                     <div className="flow-content">
                                         {pkt['tcp.flags.str'] && <span className="flow-badge">{pkt['tcp.flags.str']}</span>}
                                         {pkt['_ws.col.info']}
                                     </div>
                                 </div>
                                 
                                 {isOutgoing && <span className="flow-time">{parseFloat(pkt['frame.time_relative']).toFixed(3)}s</span>}
                             </div>
                         );
                     })
                 )}
                 <div style={{display: 'flex', justifyContent: 'center', gap: '10px', padding: '10px'}}>
                     <button disabled={page === 1} onClick={() => loadPackets(page - 1)} className="btn-secondary">Prev</button>
                     <span style={{alignSelf:'center', fontSize:'12px'}}>Page {page}</span>
                     <button onClick={() => loadPackets(page + 1)} className="btn-secondary">Next</button>
                 </div>
             </div>
             
             {selectedPacket && (
                 <div className="stream-detail" style={{height: '40%', borderTop: '1px solid var(--border-color)', overflowY: 'auto', padding: '16px', background: 'var(--bg-primary)'}}>
                     {loadingDetail ? <div>Loading details...</div> : (
                         packetDetails && <PacketDetailTree data={packetDetails._source?.layers} label={`Frame #${selectedPacket['frame.number']}`} initialExpanded={true} />
                     )}
                 </div>
             )}
        </div>
      )}
    </div>
  );
}

function App() {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [analysisType, setAnalysisType] = useState('pcap_summary');
  const [analysisResults, setAnalysisResults] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [isAiOpen, setIsAiOpen] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    let timer;
    if (loading) {
      setProgress(0);
      timer = setInterval(() => {
        setProgress(prev => {
          if (prev >= 90) return prev;
          // Fast at first, slow at end
          const increment = Math.max(1, (90 - prev) / 10);
          return Math.min(90, prev + increment);
        });
      }, 200);
    } else {
      if (progress > 0) {
        setProgress(100);
        setTimeout(() => setProgress(0), 500);
      }
    }
    return () => clearInterval(timer);
  }, [loading]);

  useEffect(() => {
    const handleWheel = (e) => {
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.1 : 0.1;
        window.electronAPI.zoom(delta);
      }
    };
    
    window.addEventListener('wheel', handleWheel, { passive: false });
    return () => window.removeEventListener('wheel', handleWheel);
  }, []);

  useEffect(() => {
    if (selectedFiles.length === 0) return;
    const timer = setTimeout(() => {
       handleAnalyze();
    }, 600);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  useEffect(() => {
    if (selectedFiles.length > 0 && !analysisResults[analysisType]) {
      handleAnalyze();
    }
  }, [analysisType, selectedFiles]);

  const handleSelectFile = async () => {
    try {
      const filePaths = await window.electronAPI.selectPcapFile();
      if (filePaths && filePaths.length > 0) {
        if (filePaths.length > 2) {
            alert("最多支持导入 2 个文件，已自动截断为前两个文件。");
            filePaths.length = 2;
        }

        setSelectedFiles(filePaths);
        setError(null);
        setAnalysisResults({});
        
        if (filePaths.length === 2) {
            setAnalysisType('correlation');
        } else if (analysisType === 'correlation') {
            setAnalysisType('pcap_summary');
        }
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleAnalyze = async () => {
    if (selectedFiles.length === 0) return;

    setLoading(true);
    setError(null);

    try {
      let result;
      if (analysisType === 'correlation') {
         if (selectedFiles.length < 2) {
             throw new Error("请选择两个文件进行对比分析");
         }
         result = await window.electronAPI.analyzeCorrelation(
             selectedFiles[0],
             selectedFiles[1]
         );
      } else if (analysisType === 'link_trace') {
         result = await window.electronAPI.analyzeLinkTrace(
             selectedFiles[0],
             selectedFiles.length > 1 ? selectedFiles[1] : null
         );
      } else {
         result = await window.electronAPI.analyzePcap(
            selectedFiles[0],
            analysisType,
            searchQuery
         );
      }
      setAnalysisResults(prev => ({ ...prev, [analysisType]: result }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };



  const renderSummaryResult = (data) => (
    <>
      <div className="summary-card">
        <h3>概览</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>总包数</label>
            <div className="value">{data.summary?.total_packets?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>总字节</label>
            <div className="value">{formatBytes(data.summary?.total_bytes || 0)}</div>
          </div>
          <div className="stat">
            <label>持续时间</label>
            <div className="value">{data.summary?.duration_seconds || 0}s</div>
          </div>
        </div>
      </div>

      <div className="charts-row">
        {data.protocols?.length > 0 && (
          <div className="chart-card">
            <h3>协议分布</h3>
            <PieChart 
              data={data.protocols} 
              total={data.summary?.total_packets || 0}
            />
          </div>
        )}

        {data.timeline?.length > 0 && (
          <div className="chart-card">
            <h3>流量时序</h3>
            <TrafficTimeline data={data} />
          </div>
        )}
      </div>

      <div className="protocol-card">
        <h3>协议详情</h3>
        {data.protocols?.map((proto, idx) => (
          <div key={idx} className="protocol-item">
            <span 
              className="proto-color" 
              style={{ backgroundColor: CHART_COLORS[idx % CHART_COLORS.length] }}
            />
            <span className="proto-name">{proto.name}</span>
            <span className="proto-count">{proto.count.toLocaleString()} 包</span>
            <span className="proto-percent">{proto.percentage}%</span>
          </div>
        ))}
      </div>

      <div className="talkers-card">
        <h3>Top 通信节点</h3>
        {data.top_talkers?.map((talker, idx) => (
          <div key={idx} className="talker-item">
            <span className="talker-ip">{talker.ip}</span>
            <span className="talker-stats">
              ↑ {talker.packets_sent} / ↓ {talker.packets_received}
            </span>
          </div>
        ))}
      </div>
    </>
  );

  const renderHttpResult = (data) => (
    <>
      <div className="summary-card">
        <h3>HTTP 统计</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>请求数</label>
            <div className="value">{data.total_requests?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>响应数</label>
            <div className="value">{data.total_responses?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>主机数</label>
            <div className="value">{data.unique_hosts || 0}</div>
          </div>
        </div>
      </div>

      <HttpPanel data={data} filePath={selectedFiles[0]} />
    </>
  );

  const renderDnsResult = (data) => (
    <>
      <div className="summary-card">
        <h3>DNS 统计</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>查询数</label>
            <div className="value">{data.total_queries?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>响应数</label>
            <div className="value">{data.total_responses?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>唯一域名</label>
            <div className="value">{data.unique_domains || 0}</div>
          </div>
        </div>
      </div>
      
      <DnsPanel data={data} filePath={selectedFiles[0]} />
    </>
  );

  const renderTlsResult = (data) => (
    <>
      <div className="summary-card">
        <h3>TLS 统计</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>握手数</label>
            <div className="value">{data.total_handshakes?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>唯一SNI</label>
            <div className="value">{data.unique_sni || 0}</div>
          </div>
          <div className="stat">
            <label>TLS版本数</label>
            <div className="value">{Object.keys(data.versions || {}).length}</div>
          </div>
        </div>
      </div>
      
      <TlsPanel data={data} filePath={selectedFiles[0]} />
    </>
  );

  const renderSecurityResult = (data) => (
    <>
      <div className="summary-card">
        <h3>威胁概览</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>高风险</label>
            <div className="value" style={{ color: '#EF4444' }}>
              {data.security_alerts?.filter(a => a.severity === 'High').length || 0}
            </div>
          </div>
          <div className="stat">
            <label>中风险</label>
            <div className="value" style={{ color: '#F59E0B' }}>
              {data.security_alerts?.filter(a => a.severity === 'Medium').length || 0}
            </div>
          </div>
          <div className="stat">
            <label>总威胁</label>
            <div className="value">{data.total_alerts || 0}</div>
          </div>
        </div>
      </div>

      {data.security_alerts?.length > 0 ? (
        <div className="protocol-card">
          <h3>威胁详情</h3>
          {data.security_alerts.map((alert, idx) => (
            <div key={idx} className={`alert-item alert-${alert.severity.toLowerCase()}`}>
              <div className="alert-header">
                <span className={`alert-badge badge-${alert.severity.toLowerCase()}`}>
                  {alert.severity}
                </span>
                <span className="alert-type">{alert.alert_type}</span>
              </div>
              <div className="alert-desc">{alert.description}</div>
              <div className="alert-meta">
                <span className="meta-label">源 IP:</span> {alert.source_ip}
                {alert.target_ip && (
                  <>
                    <span className="meta-sep">→</span>
                    <span className="meta-label">目标 IP:</span> {alert.target_ip}
                  </>
                )}
              </div>
              {alert.payload_preview && (
                <div className="alert-payload">
                  <code>{alert.payload_preview}</code>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state" style={{ height: '200px', background: 'var(--bg-card)', borderRadius: '12px' }}>
          <p style={{ fontSize: '16px', color: 'var(--accent-green)' }}>✅ 未检测到明显的安全威胁</p>
        </div>
      )}
    </>
  );

  const renderTcpResult = (data) => (
    <>
      <div className="summary-card">
        <h3>会话统计</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>总会话数</label>
            <div className="value">{data.total_sessions?.toLocaleString() || 0}</div>
          </div>
          <div className="stat">
            <label>显示会话</label>
            <div className="value">{data.tcp_sessions?.length || 0}</div>
          </div>
        </div>
      </div>

      {data.tcp_sessions?.map((session, idx) => (
        <TcpSessionCard key={idx} session={session} filePath={selectedFiles[0]} />
      ))}
    </>
  );

  const renderDiagnosticsResult = (data) => (
    <>
      <div className="summary-card">
        <h3>健康评分</h3>
        <div className="stats-grid">
          <div className="stat">
            <label>重传总数</label>
            <div className="value" style={{ color: data.total_anomalies?.Retransmission > 0 ? '#EF4444' : 'inherit' }}>
              {data.total_anomalies?.Retransmission || 0}
            </div>
          </div>
          <div className="stat">
            <label>零窗口</label>
            <div className="value" style={{ color: data.total_anomalies?.['Zero Window'] > 0 ? '#EF4444' : 'inherit' }}>
              {data.total_anomalies?.['Zero Window'] || 0}
            </div>
          </div>
          <div className="stat">
            <label>异常会话</label>
            <div className="value">{data.anomalous_sessions?.length || 0}</div>
          </div>
        </div>
      </div>

      <DiagnosticsPanel data={data} filePath={selectedFiles[0]} />
    </>
  );

  const renderResult = () => {
    const data = analysisResults[analysisType];
    if (!data) return null;
    
    switch (analysisType) {
      case 'pcap_summary':
        return renderSummaryResult(data);
      case 'http_analysis':
        return renderHttpResult(data);
      case 'dns_analysis':
        return renderDnsResult(data);
      case 'tls_analysis':
        return renderTlsResult(data);
      case 'tcp_sessions':
        return renderTcpResult(data);
      case 'tcp_anomalies':
        return renderDiagnosticsResult(data);
      case 'security_scan':
        return renderSecurityResult(data);
      case 'correlation':
        return <CorrelationPanel data={data} files={selectedFiles} />;
      case 'link_trace':
        return <LinkTracePanel data={data} files={selectedFiles} />;
      default:
        return <pre>{JSON.stringify(data, null, 2)}</pre>;
    }
  };

  const currentTypeLabel = ANALYSIS_TYPES.find(t => t.id === analysisType)?.label || '分析';

  return (
    <div className="app">
      <div className="titlebar">
        <h1>NetLens</h1>
      </div>

      <div className="content">
        <div className={`sidebar ${isSidebarOpen ? '' : 'collapsed'}`}>
          <div className="sidebar-brand" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', height: '60px' }}>
             <img src={logo} alt="Logo" style={{ width: '28px', height: '28px' }} />
             {isSidebarOpen && <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>NetLens</span>}
          </div>

          <button className="sidebar-toggle" onClick={() => setIsSidebarOpen(!isSidebarOpen)}>
            «
          </button>

          <div className="sidebar-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '16px', overflowY: 'auto' }}>
            <button className="btn-primary" onClick={handleSelectFile} title={!isSidebarOpen ? "选择文件" : ""}>
              {isSidebarOpen ? '选择 PCAP 文件' : <span style={{fontSize: '18px'}}>+</span>}
            </button>

            {selectedFiles.length > 0 && (
              <>
                <div className="file-list">
                  <h3>已选文件</h3>
                  {selectedFiles.map((file, index) => (
                    <div key={index} className="file-item">
                      {file.split('/').pop()}
                    </div>
                  ))}
                </div>

                <div className="analysis-type-section">
                  <h3>分析类型</h3>
                  <div className="analysis-type-list">
                    {ANALYSIS_TYPES.map((type) => (
                      <button
                        key={type.id}
                        className={`analysis-type-btn ${analysisType === type.id ? 'active' : ''}`}
                        onClick={() => setAnalysisType(type.id)}
                        title={!isSidebarOpen ? type.label : ""}
                      >
                        <span className="type-icon">{type.icon}</span>
                        {isSidebarOpen && <span className="type-label">{type.label}</span>}
                      </button>
                    ))}
                  </div>
                </div>


              </>
            )}
          </div>
          
          <button className="btn-settings" onClick={() => setIsSettingsOpen(true)} title={!isSidebarOpen ? "设置" : ""}>
            <span>⚙️</span>
            {isSidebarOpen && <span>设置</span>}
          </button>
          
          <button className="btn-settings" onClick={() => setIsAiOpen(true)} title={!isSidebarOpen ? "AI 分析师" : ""}>
            <span>🤖</span>
            {isSidebarOpen && <span>AI 分析师</span>}
          </button>
        </div>

        <div className="main-panel">
          {error && (
            <div className="error-box">
              <strong>错误：</strong> {error}
            </div>
          )}

          {loading && (
            <div className="loading-box">
              <div className="progress-container">
                <div 
                    className="progress-bar" 
                    style={{ width: `${Math.round(progress)}%`, animation: 'none', transition: 'width 0.2s ease-out' }}
                ></div>
              </div>
              <p>正在进行{currentTypeLabel}... {Math.round(progress)}%</p>
            </div>
          )}

          {analysisResults[analysisType] && !loading && (
            <div 
                className="result-container"
                style={{
                    overflowY: ['link_trace', 'correlation'].includes(analysisType) ? 'hidden' : 'auto',
                    padding: ['link_trace', 'correlation'].includes(analysisType) ? '0' : '24px 32px',
                    display: ['link_trace', 'correlation'].includes(analysisType) ? 'flex' : 'block'
                }}
            >
              <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', padding: ['link_trace', 'correlation'].includes(analysisType) ? '24px 32px 0 32px' : '0'}}>
                  <div>
                      <h2 style={{margin: 0}}>{currentTypeLabel}结果</h2>
                      {selectedFiles.length > 0 && analysisType !== 'correlation' && (
                          <div style={{fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px'}}>
                              正在分析: {selectedFiles[0].split('/').pop()}
                          </div>
                      )}
                  </div>
                  {['tcp_sessions', 'http_analysis', 'dns_analysis', 'tls_analysis', 'tcp_anomalies', 'security_scan'].includes(analysisType) && (
                      <div style={{width: '300px'}}>
                          <SearchBar value={searchQuery} onChange={setSearchQuery} placeholder="Filter results..." />
                      </div>
                  )}
              </div>
              {renderResult()}
            </div>
          )}

          {!analysisResults[analysisType] && !loading && !error && (
            <div className="empty-state">
              <h2>欢迎使用 NetLens</h2>
              <p>选择一个 PCAP 文件开始分析</p>
            </div>
          )}
        </div>
      </div>
      <SettingsModal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
      <AiChatSidebar isOpen={isAiOpen} onClose={() => setIsAiOpen(false)} filePaths={selectedFiles} />
    </div>
  );
}

export default App;
