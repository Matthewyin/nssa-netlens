import React, { useState, useEffect } from 'react';
import './ProgressOverlay.css';

const ProgressOverlay = ({ loading, currentTypeLabel }) => {
  const [progress, setProgress] = useState(0);
  const [progressMessage, setProgressMessage] = useState('');

  useEffect(() => {
    let timer;
    let cleanupListener;

    if (loading) {
      setProgress(0);
      setProgressMessage(`正在进行${currentTypeLabel}...`);
      
      // Fake progress for visual feedback
      timer = setInterval(() => {
        setProgress(prev => {
          if (prev >= 95) return prev;
          // Slow down as it approaches 95%
          const increment = Math.max(0.5, (95 - prev) / 50);
          return Math.min(95, prev + increment);
        });
      }, 200);

      // Listen for real progress messages
      if (window.electronAPI?.onAnalysisProgress) {
          cleanupListener = window.electronAPI.onAnalysisProgress((data) => {
              if (data && data.message) {
                  setProgressMessage(data.message);
              }
          });
      }
    } else {
      if (progress > 0) {
        setProgress(100);
        setTimeout(() => {
            setProgress(0);
            setProgressMessage('');
        }, 500);
      }
    }
    
    return () => {
        clearInterval(timer);
        if (window.electronAPI?.offAnalysisProgress) {
            window.electronAPI.offAnalysisProgress();
        }
    };
  }, [loading, currentTypeLabel]);

  if (!loading && progress === 0) return null;

  return (
    <div className="loading-box">
      <div className="progress-container">
        <div 
            className="progress-bar" 
            style={{ width: `${Math.round(progress)}%`, animation: 'none', transition: 'width 0.2s ease-out' }}
        ></div>
      </div>
      <p>{progressMessage} ({Math.round(progress)}%)</p>
    </div>
  );
};

export default React.memo(ProgressOverlay);
