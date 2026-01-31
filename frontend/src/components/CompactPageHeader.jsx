import React from 'react';
import ReportExport from '../ReportExport';
import './CompactPageHeader.css';

function CompactPageHeader({ title, fileName, stats = [], extraContent, onExport, exportDisabled }) {
    return (
        <div className="compact-header">
            <div className="header-left">
                <h2 className="header-title">{title}</h2>
                {fileName && <span className="header-filename">{fileName}</span>}
            </div>

            <div className="header-center">
                {stats.map((stat, idx) => (
                    <div key={idx} className="header-stat">
                        <span className="stat-label">{stat.label}</span>
                        <span className={`stat-value ${stat.colorClass || ''}`}>
                            {stat.value}
                        </span>
                        {idx < stats.length - 1 && <div className="stat-divider" />}
                    </div>
                ))}
            </div>

            <div className="header-right">
                {extraContent}
                <ReportExport onExport={onExport} disabled={exportDisabled} />
            </div>
        </div>
    );
}

export default CompactPageHeader;
