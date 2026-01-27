import { useState, useEffect, useRef } from 'react';
import './SettingsModal.css';

function SettingsModal({ isOpen, onClose }) {
  const [outputDir, setOutputDir] = useState('');
  const [profiles, setProfiles] = useState([]);
  const [activeProfileId, setActiveProfileId] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [saveStatus, setSaveStatus] = useState('saved');
  const [isLoaded, setIsLoaded] = useState(false);
  const saveTimeoutRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      loadSettings();
      setVerifyResult(null);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isLoaded) return;
    
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);

    setSaveStatus('saving');
    
    saveTimeoutRef.current = setTimeout(async () => {
      try {
        await window.electronAPI.saveSettings({ 
          outputDir,
          aiProfiles: profiles,
          activeProfileId
        });
        setSaveStatus('saved');
      } catch (err) {
        console.error('Auto-save failed:', err);
        setSaveStatus('error');
      }
    }, 800);

    return () => {
        if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    };
  }, [outputDir, profiles, activeProfileId, isLoaded]);

  const loadSettings = async () => {
    try {
      if (window.electronAPI.getSettings) {
          const settings = await window.electronAPI.getSettings();
          setOutputDir(settings.outputDir || '');
          setProfiles(settings.aiProfiles || []);
          setActiveProfileId(settings.activeProfileId || '');
          setIsLoaded(true);
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

  const activeProfile = profiles.find(p => p.id === activeProfileId) || {};

  const handleProfileChange = (key, value) => {
    setProfiles(prev => prev.map(p => 
        p.id === activeProfileId ? { ...p, [key]: value } : p
    ));
    setVerifyResult(null);
  };

  const handleAddProfile = () => {
      const newId = Date.now().toString();
      const newProfile = { id: newId, name: 'New Profile', apiKey: '', baseUrl: '', model: '' };
      setProfiles([...profiles, newProfile]);
      setActiveProfileId(newId);
      setVerifyResult(null);
  };

  const handleDeleteProfile = () => {
      if (profiles.length <= 1) return;
      const newProfiles = profiles.filter(p => p.id !== activeProfileId);
      setProfiles(newProfiles);
      setActiveProfileId(newProfiles[0].id);
      setVerifyResult(null);
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    setVerifyResult(null);
    try {
      const result = await window.electronAPI.verifyAiConfig(activeProfile);
      if (result.success) {
        setVerifyResult({ success: true, message: '连接成功' });
      } else {
        setVerifyResult({ success: false, message: result.error });
      }
    } catch (err) {
      setVerifyResult({ success: false, message: err.message });
    } finally {
      setIsVerifying(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <div style={{display:'flex', alignItems:'center', gap:'12px'}}>
            <h2>设置</h2>
            {isLoaded && (
                <span className={`save-status status-${saveStatus}`}>
                  {saveStatus === 'saved' && '已保存'}
                  {saveStatus === 'saving' && '保存中...'}
                  {saveStatus === 'error' && '保存失败'}
                </span>
            )}
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="modal-body">
          <div className="setting-section">
            <h3 className="section-title">常规设置</h3>
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

          <div className="setting-section">
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
                <h3 className="section-title" style={{margin: 0, border: 'none'}}>AI 助手配置 (LLM)</h3>
                <div className="profile-actions">
                    <button className="btn-icon" onClick={handleAddProfile} title="新建配置">
                        <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    </button>
                    {profiles.length > 1 && (
                        <button className="btn-icon danger" onClick={handleDeleteProfile} title="删除当前配置">
                             <svg viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    )}
                </div>
            </div>
            
            <div className="setting-item">
                <label>选择配置</label>
                <select 
                    className="text-input" 
                    value={activeProfileId} 
                    onChange={(e) => setActiveProfileId(e.target.value)}
                >
                    {profiles.map(p => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                </select>
            </div>

            {activeProfileId && (
                <>
                    <div className="setting-item">
                      <label>配置名称</label>
                      <input 
                        type="text" 
                        className="text-input"
                        value={activeProfile.name} 
                        onChange={(e) => handleProfileChange('name', e.target.value)}
                        placeholder="例如: GPT-4, DeepSeek" 
                      />
                    </div>
                    <div className="setting-item">
                      <label>API Key</label>
                      <input 
                        type="password" 
                        className="text-input"
                        value={activeProfile.apiKey} 
                        onChange={(e) => handleProfileChange('apiKey', e.target.value)}
                        placeholder="sk-..." 
                      />
                    </div>
                    <div className="setting-item">
                      <label>API Base URL</label>
                      <input 
                        type="text" 
                        className="text-input"
                        value={activeProfile.baseUrl} 
                        onChange={(e) => handleProfileChange('baseUrl', e.target.value)}
                        placeholder="https://api.openai.com/v1" 
                      />
                    </div>
                    <div className="setting-item">
                      <label>模型名称 (Model)</label>
                      <input 
                        type="text" 
                        className="text-input"
                        value={activeProfile.model} 
                        onChange={(e) => handleProfileChange('model', e.target.value)}
                        placeholder="gpt-4-turbo-preview" 
                      />
                    </div>
                    
                    <div className="setting-item" style={{display: 'flex', alignItems: 'center', gap: '12px'}}>
                        <button 
                          className="btn-secondary" 
                          onClick={handleVerify} 
                          disabled={isVerifying || !activeProfile.apiKey}
                        >
                          {isVerifying ? '验证中...' : '验证连接'}
                        </button>
                        {verifyResult && (
                            <span className={verifyResult.success ? 'verify-success' : 'verify-error'}>
                                {verifyResult.success ? '✅ ' : '❌ '}{verifyResult.message}
                            </span>
                        )}
                    </div>
                </>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn-save" onClick={onClose}>关闭</button>
        </div>
      </div>
    </div>
  );
}

export default SettingsModal;
