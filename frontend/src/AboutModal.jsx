import React from 'react';
import './SettingsModal.css';
import logo from './assets/icon.svg';

function AboutModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '400px' }}>
        <div className="modal-header">
          <h2>关于 NetLens</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="modal-body" style={{ padding: '32px 24px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '24px' }}>
            <img src={logo} alt="Logo" style={{ width: '64px', height: '64px', marginBottom: '16px' }} />
            <h3 style={{ margin: '0 0 8px 0', fontSize: '20px', fontWeight: '600' }}>NetLens</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: '0' }}>
              现代化的 PCAP 分析工具
            </p>
          </div>
          
          <div className="setting-section">
            <div className="setting-item">
              <label>作者</label>
              <div className="text-input" style={{ background: 'var(--bg-tertiary)', userSelect: 'text' }}>AlkaiDY</div>
            </div>
            <div className="setting-item">
              <label>联系邮箱</label>
              <div className="text-input" style={{ background: 'var(--bg-tertiary)', userSelect: 'text' }}>tccio2023@gmail.com</div>
            </div>
            <div className="setting-item">
              <label>当前版本</label>
              <div className="text-input" style={{ background: 'var(--bg-tertiary)', userSelect: 'text' }}>v0.3.0</div>
            </div>
            <div className="setting-item">
              <label>开源仓库</label>
              <div className="input-group">
                <input 
                  type="text" 
                  value="https://github.com/Matthewyin/nssa-netlens" 
                  readOnly 
                  className="text-input"
                  style={{ background: 'var(--bg-tertiary)' }}
                />
                <button 
                  className="btn-secondary" 
                  onClick={() => window.electronAPI ? window.electronAPI.openExternal('https://github.com/Matthewyin/nssa-netlens') : window.open('https://github.com/Matthewyin/nssa-netlens', '_blank')}
                >
                  访问
                </button>
              </div>
            </div>
          </div>
        </div>
        
        <div className="modal-footer" style={{ justifyContent: 'center' }}>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
            © 2026 NetLens Team. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}

export default AboutModal;
