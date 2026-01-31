import React, { useState } from 'react';
import './ReportExport.css';
import { useToast } from './Toast';

const ReportExport = ({ onExport, disabled = false }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const { showToast, showWarning } = useToast();

  const handleExport = async (format) => {
    if (disabled) return;
    
    setIsExporting(true);
    setIsOpen(false);
    
    try {
      if (onExport) {
        await onExport(format);
      } else if (window.electronAPI?.exportReport) {
        await window.electronAPI.exportReport(format);
        showToast('报告导出成功', 'success');
      } else {
        showWarning('导出功能暂未实现');
      }
    } catch (error) {
      console.error('Export failed:', error);
      showToast('导出失败: ' + error.message, 'error');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="report-export-container">
      <button 
        className={`btn-export ${isExporting ? 'loading' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
        disabled={disabled || isExporting}
        title="导出分析报告"
      >
        <span className="icon-export">📤</span>
        {isExporting ? '导出中...' : '导出报告'}
      </button>

      {isOpen && (
        <>
          <div className="export-overlay" onClick={() => setIsOpen(false)} />
          <div className="export-menu">
            <div className="export-menu-header">选择格式</div>
            <button className="export-item" onClick={() => handleExport('html')}>
              <span className="format-icon html">H</span>
              <div className="format-info">
                <span className="format-name">HTML 报告</span>
                <span className="format-desc">包含图表和交互式视图</span>
              </div>
            </button>
            <button className="export-item" onClick={() => handleExport('json')}>
              <span className="format-icon json">J</span>
              <div className="format-info">
                <span className="format-name">JSON 数据</span>
                <span className="format-desc">原始分析数据，适合二次开发</span>
              </div>
            </button>
            <button className="export-item disabled" title="暂未支持">
              <span className="format-icon pdf">P</span>
              <div className="format-info">
                <span className="format-name">PDF 文档</span>
                <span className="format-desc">适合打印和归档 (Coming Soon)</span>
              </div>
            </button>
          </div>
        </>
      )}
    </div>
  );
};

export default ReportExport;
