import { useState } from 'react';
import './SequenceDiagram.css';

const EVENT_HEIGHT = 40;
const HEADER_HEIGHT = 30;
const HOST_SPACING = 300;
const PADDING_TOP = 40;

function SequenceDiagram({ events, clientIp, serverIp, onPacketClick }) {
  const [selectedEvent, setSelectedEvent] = useState(null);

  if (!events || events.length === 0) return <div className="seq-empty">No events to display</div>;

  const height = events.length * EVENT_HEIGHT + PADDING_TOP * 2;
  const width = HOST_SPACING + 200; // Center diagram
  
  const clientX = 100;
  const serverX = 100 + HOST_SPACING;

  // Render logic
  const renderArrow = (evt, index) => {
    const y = PADDING_TOP + index * EVENT_HEIGHT;
    const isClientToServer = evt.src === clientIp; 
    
    // Determine color class and marker
    let typeClass = 'color-normal';
    let markerId = 'arrow-normal';
    
    if (evt.types.includes('Retransmission')) { typeClass = 'color-retransmission'; markerId = 'arrow-retransmission'; }
    else if (evt.types.includes('Reset')) { typeClass = 'color-reset'; markerId = 'arrow-reset'; }
    else if (evt.types.includes('Duplicate ACK')) { typeClass = 'color-dup'; markerId = 'arrow-dup'; }
    else if (evt.types.includes('Zero Window')) { typeClass = 'color-window'; markerId = 'arrow-window'; }

    const startX = isClientToServer ? clientX : serverX;
    const endX = isClientToServer ? serverX : clientX;
    
    const lineOffset = 10;
    const x1 = isClientToServer ? startX + lineOffset : startX - lineOffset;
    const x2 = isClientToServer ? endX - lineOffset : endX + lineOffset;

    return (
      <g 
        key={index} 
        onClick={() => { 
          setSelectedEvent(evt); 
          if (onPacketClick) onPacketClick(evt);
        }} 
        className="seq-group"
      >
        {/* Invisible clickable area */}
        <line x1={x1} y1={y} x2={x2} y2={y} className="seq-arrow-bg" />
        
        {/* Visible arrow */}
        <line 
          x1={x1} y1={y} x2={x2} y2={y} 
          className={`seq-arrow ${typeClass}`} 
          markerEnd={`url(#${markerId})`}
        />
        
        {/* Label */}
        <text x={(x1 + x2) / 2} y={y - 5} textAnchor="middle" className="seq-label">
          {evt.tcp?.seq ? `Seq=${evt.tcp.seq}` : ''} 
          {evt.types.length > 0 ? ` [${evt.types[0]}]` : ''}
        </text>
        
        {/* Time label on side */}
        <text x={10} y={y + 4} className="seq-label" style={{ textAnchor: 'start' }}>
          {parseFloat(evt.time).toFixed(3)}s
        </text>
      </g>
    );
  };

  return (
    <div>
      <div className="seq-container">
        <svg width={width} height={height} className="seq-svg">
          <defs>
            <marker id="arrow-normal" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#06b6d4" />
            </marker>
            <marker id="arrow-retransmission" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
            </marker>
            <marker id="arrow-reset" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#d946ef" />
            </marker>
            <marker id="arrow-dup" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#eab308" />
            </marker>
            <marker id="arrow-window" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#f97316" />
            </marker>
          </defs>
          
          {/* Host Lines */}
          <line x1={clientX} y1={HEADER_HEIGHT} x2={clientX} y2={height} className="seq-line" />
          <line x1={serverX} y1={HEADER_HEIGHT} x2={serverX} y2={height} className="seq-line" />
          
          {/* Host Labels */}
          <text x={clientX} y={20} textAnchor="middle" className="seq-host-label">Client</text>
          <text x={serverX} y={20} textAnchor="middle" className="seq-host-label">Server</text>
          
          {/* Events */}
          {events.map((evt, idx) => renderArrow(evt, idx))}
        </svg>
      </div>
    </div>
  );
}

export default SequenceDiagram;
