import { useState, memo, useEffect, useRef } from 'react';
import '../LinkTracePanel.css';

const DEFAULT_COLUMNS = {
    seq: { label: '#', visible: true, required: true, width: 50 },
    relative_time_ms: { label: 'Time', visible: true, required: true, width: 80 },
    size: { label: 'Size', visible: true, required: true, width: 60 },
    flags: { label: 'Flags', visible: true, required: true, width: 60 },
    seq_num: { label: 'Seq', visible: false, required: false, width: 80 },
    ack_num: { label: 'Ack', visible: false, required: false, width: 80 },
    info: { label: 'Info', visible: false, required: false, flex: 1, minWidth: 200 }, // Added minWidth to prevent squashing
    frame_number: { label: 'Frame', visible: false, required: false, width: 60 },
    window_size: { label: 'Window', visible: false, required: false, width: 70 },
    checksum: { label: 'Checksum', visible: false, required: false, width: 80 },
    options: { label: 'Options', visible: false, required: false, width: 100 },
};

const PacketTable = memo(function PacketTable({ packets, totalPackets, onExportCSV, pcapFile, onPacketClick, selectedPacket }) {
    const [columns, setColumns] = useState(DEFAULT_COLUMNS);
    const [showColumnSelector, setShowColumnSelector] = useState(false);
    const columnSelectorRef = useRef(null);

    // Click outside to close column selector
    useEffect(() => {
        function handleClickOutside(event) {
            if (columnSelectorRef.current && !columnSelectorRef.current.contains(event.target)) {
                setShowColumnSelector(false);
            }
        }
        if (showColumnSelector) {
            document.addEventListener("mousedown", handleClickOutside);
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [showColumnSelector]);

    if (!packets || packets.length === 0) {
        return <div className="no-packets">No packet data available</div>;
    }

    const visibleColumns = Object.entries(columns).filter(([_, config]) => config.visible);

    // Calculate grid template columns
    // Use minmax to ensure columns don't shrink below their defined width
    const gridTemplateColumns = visibleColumns.map(([_, config]) => 
        config.flex 
            ? `minmax(${config.minWidth || 100}px, 1fr)` 
            : `${config.width}px`
    ).join(' ');

    const toggleColumn = (key) => {
        if (columns[key].required) return;
        setColumns(prev => ({
            ...prev,
            [key]: { ...prev[key], visible: !prev[key].visible }
        }));
    };

    const formatValue = (key, value) => {
        if (key === 'relative_time_ms') return `+${value.toFixed(2)}ms`;
        if (key === 'size') return `${value}B`;
        if (value === null || value === undefined) return '-';
        return String(value);
    };

    const handleExportCSV = () => {
        const headers = visibleColumns.map(([_, config]) => config.label);
        const rows = packets.map(pkt => 
            visibleColumns.map(([key, _]) => formatValue(key, pkt[key]))
        );
        const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'packets.csv';
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="packet-table-container">
            <div className="packet-table-toolbar">
                <div className="toolbar-left">
                    <span className="packet-count">
                        {packets.length} packets
                    </span>
                </div>
                <div className="toolbar-right">
                    <div className="column-selector-wrapper" ref={columnSelectorRef}>
                        <button 
                            className="toolbar-btn"
                            onClick={() => setShowColumnSelector(!showColumnSelector)}
                        >
                            Columns ▼
                        </button>
                        {showColumnSelector && (
                            <div className="column-selector-dropdown">
                                {Object.entries(columns).map(([key, config]) => (
                                    <label key={key} className={config.required ? 'disabled' : ''}>
                                        <input
                                            type="checkbox"
                                            checked={config.visible}
                                            onChange={() => toggleColumn(key)}
                                            disabled={config.required}
                                        />
                                        {config.label}
                                    </label>
                                ))}
                            </div>
                        )}
                    </div>
                    <button className="toolbar-btn" onClick={handleExportCSV}>
                        Export CSV
                    </button>
                </div>
            </div>

            {/* Scrollable container for both Header and Body */}
            <div className="packet-table-scroll-container" style={{ flex: 1, overflow: 'auto', width: '100%' }}>
                <div className="packet-table-inner" style={{ minWidth: '100%', width: 'max-content' }}>
                    <div className="v-header" style={{ display: 'grid', gridTemplateColumns: gridTemplateColumns }}>
                        {visibleColumns.map(([key, config]) => (
                            <div key={key} className="v-header-cell">{config.label}</div>
                        ))}
                    </div>

                    <div className="packet-list">
                        {packets.map((pkt) => {
                            const isSelected = selectedPacket && selectedPacket.frame_number === pkt.frame_number;
                            return (
                                <div 
                                    key={pkt.frame_number}
                                    className={`v-row ${pkt.is_retransmission ? 'retransmission' : ''} ${isSelected ? 'selected' : ''}`}
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: gridTemplateColumns,
                                        alignItems: 'center',
                                        height: '36px'
                                    }}
                                    onClick={() => onPacketClick && onPacketClick(pkt)}
                                >
                                    {visibleColumns.map(([key, _]) => (
                                        <div key={key} className={`v-cell col-${key}`}>
                                            {formatValue(key, pkt[key])}
                                        </div>
                                    ))}
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>
        </div>
    );
});

export default PacketTable;
