import { useState } from 'react';
import './PacketDetailTree.css';

function PacketDetailTree({ data, label, initialExpanded = false }) {
  const [isExpanded, setIsExpanded] = useState(initialExpanded);

  if (typeof data !== 'object' || data === null) {
    return (
      <div className="pdt-leaf">
        <span className="pdt-leaf-label">{label}: </span>
        <span className="pdt-leaf-value">{String(data)}</span>
      </div>
    );
  }

  if (Array.isArray(data)) {
    return (
      <div className="pdt-node">
        <div className="pdt-node-header" onClick={() => setIsExpanded(!isExpanded)}>
          <span className="pdt-toggle">{isExpanded ? '▼' : '▶'}</span>
          <span className="pdt-label">{label}</span>
          <span className="pdt-count">[{data.length}]</span>
        </div>
        {isExpanded && (
          <div className="pdt-children">
            {data.map((item, idx) => (
              <PacketDetailTree key={idx} label={String(idx)} data={item} />
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="pdt-node">
      <div className="pdt-node-header" onClick={() => setIsExpanded(!isExpanded)}>
        <span className="pdt-toggle">{isExpanded ? '▼' : '▶'}</span>
        <span className="pdt-label">{label}</span>
      </div>
      {isExpanded && (
        <div className="pdt-children">
          {Object.entries(data).map(([key, value]) => (
            <PacketDetailTree key={key} label={key} data={value} />
          ))}
        </div>
      )}
    </div>
  );
}

export default PacketDetailTree;
