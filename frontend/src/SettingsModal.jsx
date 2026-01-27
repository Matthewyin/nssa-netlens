import { useState, useEffect } from 'react';
import './SettingsModal.css';

function SettingsModal({ isOpen, onClose }) {
  const [outputDir, setOutputDir] = useState('');

  useEffect(() => {
    if (isOpen) {
      loadSettings();
    }
  }, [isOpen]);

  const loadSettings = async () => {
    try {
      // Assuming exposed via preload.js as window.electronAPI.getSettings
      // I need to update preload.js too!
      if (window.electronAPI.getSettings) {
          const settings = await window.electronAPI.getSettings();
          setOutputDir(settings.outputDir || '');
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    }
  };

  const handleSelectDir = async () => {
    try {
      const path = await window.electronAPI.selectOutputDirectory();
      if (path) {
        setOutputDir(path);
      }
    } catch (err) {
      console.error('Failed to select directory:', err);
    }
  };

  const handleSave = async () => {
    try {
      await window.electronAPI.saveSettings({ outputDir });
      onClose();
    } catch (err) {
      console.error('Failed to save settings:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h2>设置</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="modal-body">
          <div className="setting-item">
            <label>报告保存目录</label>
            <div className="input-group">
              <input 
                type="text" 
                value={outputDir} 
                readOnly 
                placeholder="选择目录..." 
              />
              <button className="btn-secondary" onClick={handleSelectDir}>
                浏览...
              </button>
            </div>
            <p className="setting-desc">分析报告（如故障诊断日志）将保存到此目录。</p>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn-cancel" onClick={onClose}>取消</button>
          <button className="btn-save" onClick={handleSave}>保存</button>
        </div>
      </div>
    </div>
  );
}

export default SettingsModal;
