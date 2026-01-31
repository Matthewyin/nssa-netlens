import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import './Toast.css';
import { parseError, getErrorIcon, getErrorSeverity } from './utils/errorHandler';

const ToastContext = createContext(null);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = 'info', duration = 5000) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type, duration }]);
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showError = useCallback((error) => {
    const parsed = parseError(error);
    const icon = getErrorIcon(parsed.type);
    const severity = getErrorSeverity(parsed.code);
    return addToast(`${icon} ${parsed.message}`, severity, 6000);
  }, [addToast]);

  const showSuccess = useCallback((message) => {
    return addToast(`✅ ${message}`, 'success', 3000);
  }, [addToast]);

  const showWarning = useCallback((message) => {
    return addToast(`⚠️ ${message}`, 'warning', 5000);
  }, [addToast]);

  const showInfo = useCallback((message) => {
    return addToast(`ℹ️ ${message}`, 'info', 4000);
  }, [addToast]);

  return (
    <ToastContext.Provider value={{ addToast, removeToast, showError, showSuccess, showWarning, showInfo }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
}

function ToastContainer({ toasts, onRemove }) {
  return (
    <div className="toast-container">
      {toasts.map(toast => (
        <ToastItem key={toast.id} toast={toast} onRemove={onRemove} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onRemove }) {
  const [isExiting, setIsExiting] = useState(false);

  useEffect(() => {
    const exitTimer = setTimeout(() => {
      setIsExiting(true);
    }, toast.duration - 300);

    const removeTimer = setTimeout(() => {
      onRemove(toast.id);
    }, toast.duration);

    return () => {
      clearTimeout(exitTimer);
      clearTimeout(removeTimer);
    };
  }, [toast, onRemove]);

  const handleClose = () => {
    setIsExiting(true);
    setTimeout(() => onRemove(toast.id), 300);
  };

  return (
    <div className={`toast-item toast-${toast.type} ${isExiting ? 'toast-exit' : ''}`}>
      <span className="toast-message">{toast.message}</span>
      <button className="toast-close" onClick={handleClose}>×</button>
    </div>
  );
}

export function ErrorBanner({ error, onDismiss, showDetails = false }) {
  const [detailsVisible, setDetailsVisible] = useState(false);
  
  if (!error) return null;
  
  const parsed = parseError(error);
  const icon = getErrorIcon(parsed.type);
  const severity = getErrorSeverity(parsed.code);

  return (
    <div className={`error-banner error-banner-${severity}`}>
      <div className="error-banner-content">
        <span className="error-banner-icon">{icon}</span>
        <span className="error-banner-message">{parsed.message}</span>
        {showDetails && parsed.details && parsed.details !== parsed.message && (
          <button 
            className="error-banner-details-btn"
            onClick={() => setDetailsVisible(!detailsVisible)}
          >
            {detailsVisible ? '隐藏详情' : '显示详情'}
          </button>
        )}
      </div>
      {detailsVisible && parsed.details && (
        <div className="error-banner-details">
          <code>{parsed.details}</code>
        </div>
      )}
      {onDismiss && (
        <button className="error-banner-dismiss" onClick={onDismiss}>×</button>
      )}
    </div>
  );
}
