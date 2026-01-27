import { useState } from 'react';

function PacketDetailTree({ data, label, initialExpanded = false }) {
  const [isExpanded, setIsExpanded] = useState(initialExpanded);

  if (typeof data !== 'object' || data === null) {
    return (
      <div style={{ paddingLeft: '20px', fontFamily: 'monospace', fontSize: '13px', lineHeight: '1.5' }}>
        <span style={{ color: 'var(--text-muted)' }}>{label}: </span>
        <span style={{ color: 'var(--accent-blue)' }}>{String(data)}</span>
      </div>
    );
  }

  // Handle array
  if (Array.isArray(data)) {
      return (
        <div style={{ paddingLeft: '10px' }}>
          <div 
            onClick={() => setIsExpanded(!isExpanded)} 
            style={{ cursor: 'pointer', fontFamily: 'monospace', fontSize: '13px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', lineHeight: '1.5' }}
          >
            <span style={{ marginRight: '5px', fontSize: '10px' }}>{isExpanded ? '▼' : '▶'}</span>
            <span style={{ fontWeight: 600 }}>{label}</span>
            <span style={{ color: 'var(--text-muted)', marginLeft: '5px' }}>[{data.length}]</span>
          </div>
          {isExpanded && (
            <div style={{ borderLeft: '1px solid var(--border-color)', marginLeft: '5px' }}>
              {data.map((item, idx) => (
                <PacketDetailTree key={idx} label={String(idx)} data={item} />
              ))}
            </div>
          )}
        </div>
      );
  }

  return (
    <div style={{ paddingLeft: '10px' }}>
      <div 
        onClick={() => setIsExpanded(!isExpanded)} 
        style={{ cursor: 'pointer', fontFamily: 'monospace', fontSize: '13px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', lineHeight: '1.5' }}
      >
        <span style={{ marginRight: '5px', fontSize: '10px' }}>{isExpanded ? '▼' : '▶'}</span>
        <span style={{ fontWeight: 600 }}>{label}</span>
      </div>
      {isExpanded && (
        <div style={{ borderLeft: '1px solid var(--border-color)', marginLeft: '5px' }}>
          {Object.entries(data).map(([key, value]) => (
            <PacketDetailTree key={key} label={key} data={value} />
          ))}
        </div>
      )}
    </div>
  );
}

export default PacketDetailTree;
