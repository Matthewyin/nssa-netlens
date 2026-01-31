/**
 * Unified Error Handler for NetLens
 * Converts technical errors into user-friendly messages
 */

// Error codes and their user-friendly messages
const ERROR_MESSAGES = {
  // File errors
  FILE_NOT_FOUND: '找不到文件，请检查文件路径是否正确',
  FILE_ACCESS_DENIED: '无法访问文件，请检查文件权限',
  FILE_INVALID_FORMAT: '文件格式不支持，请选择有效的 PCAP/PCAPNG 文件',
  FILE_TOO_LARGE: '文件过大，分析可能需要较长时间',
  FILE_CORRUPTED: '文件已损坏或格式不正确',
  
  // Analysis errors
  ANALYSIS_FAILED: '分析过程中发生错误，请重试',
  ANALYSIS_TIMEOUT: '分析超时，文件可能过大',
  ANALYSIS_NO_DATA: '未找到可分析的数据',
  
  // Python backend errors
  PYTHON_NOT_FOUND: 'Python 环境未配置，请检查安装',
  PYTHON_CRASHED: '分析引擎异常退出，请重试',
  TSHARK_NOT_FOUND: '未找到 Wireshark/Tshark，请先安装',
  
  // Network errors
  NETWORK_ERROR: '网络连接错误',
  
  // Generic
  UNKNOWN_ERROR: '发生未知错误，请重试',
};

// Error type classification
const ERROR_TYPES = {
  FILE: 'file',
  ANALYSIS: 'analysis',
  SYSTEM: 'system',
  NETWORK: 'network',
};

/**
 * Parse error message and extract meaningful information
 * @param {Error|string} error - The error object or message
 * @returns {Object} Parsed error with code, type, message, and details
 */
export function parseError(error) {
  const errorStr = error?.message || error?.toString() || String(error);
  const lowerError = errorStr.toLowerCase();
  
  // File-related errors
  if (lowerError.includes('no such file') || lowerError.includes('enoent')) {
    return {
      code: 'FILE_NOT_FOUND',
      type: ERROR_TYPES.FILE,
      message: ERROR_MESSAGES.FILE_NOT_FOUND,
      details: errorStr,
    };
  }
  
  if (lowerError.includes('permission denied') || lowerError.includes('eacces')) {
    return {
      code: 'FILE_ACCESS_DENIED',
      type: ERROR_TYPES.FILE,
      message: ERROR_MESSAGES.FILE_ACCESS_DENIED,
      details: errorStr,
    };
  }
  
  if (lowerError.includes('invalid pcap') || lowerError.includes('not a pcap')) {
    return {
      code: 'FILE_INVALID_FORMAT',
      type: ERROR_TYPES.FILE,
      message: ERROR_MESSAGES.FILE_INVALID_FORMAT,
      details: errorStr,
    };
  }
  
  // Python/Tshark errors
  if (lowerError.includes('tshark') && lowerError.includes('not found')) {
    return {
      code: 'TSHARK_NOT_FOUND',
      type: ERROR_TYPES.SYSTEM,
      message: ERROR_MESSAGES.TSHARK_NOT_FOUND,
      details: errorStr,
    };
  }
  
  if (lowerError.includes('python') && (lowerError.includes('not found') || lowerError.includes('spawn'))) {
    return {
      code: 'PYTHON_NOT_FOUND',
      type: ERROR_TYPES.SYSTEM,
      message: ERROR_MESSAGES.PYTHON_NOT_FOUND,
      details: errorStr,
    };
  }
  
  if (lowerError.includes('exited with code') || lowerError.includes('process exit')) {
    return {
      code: 'PYTHON_CRASHED',
      type: ERROR_TYPES.SYSTEM,
      message: ERROR_MESSAGES.PYTHON_CRASHED,
      details: errorStr,
    };
  }
  
  // JSON parse errors (from backend)
  if (lowerError.includes('json') && lowerError.includes('parse')) {
    return {
      code: 'ANALYSIS_FAILED',
      type: ERROR_TYPES.ANALYSIS,
      message: ERROR_MESSAGES.ANALYSIS_FAILED,
      details: errorStr,
    };
  }
  
  // Analysis errors
  if (lowerError.includes('timeout')) {
    return {
      code: 'ANALYSIS_TIMEOUT',
      type: ERROR_TYPES.ANALYSIS,
      message: ERROR_MESSAGES.ANALYSIS_TIMEOUT,
      details: errorStr,
    };
  }
  
  if (lowerError.includes('no data') || lowerError.includes('empty')) {
    return {
      code: 'ANALYSIS_NO_DATA',
      type: ERROR_TYPES.ANALYSIS,
      message: ERROR_MESSAGES.ANALYSIS_NO_DATA,
      details: errorStr,
    };
  }
  
  // Network errors
  if (lowerError.includes('network') || lowerError.includes('fetch') || lowerError.includes('connection')) {
    return {
      code: 'NETWORK_ERROR',
      type: ERROR_TYPES.NETWORK,
      message: ERROR_MESSAGES.NETWORK_ERROR,
      details: errorStr,
    };
  }
  
  // Default: unknown error
  return {
    code: 'UNKNOWN_ERROR',
    type: ERROR_TYPES.ANALYSIS,
    message: ERROR_MESSAGES.UNKNOWN_ERROR,
    details: errorStr,
  };
}

/**
 * Get user-friendly error message
 * @param {Error|string} error - The error object or message
 * @returns {string} User-friendly error message
 */
export function formatUserFriendlyError(error) {
  const parsed = parseError(error);
  return parsed.message;
}

/**
 * Get error icon based on error type
 * @param {string} type - Error type
 * @returns {string} Emoji icon
 */
export function getErrorIcon(type) {
  switch (type) {
    case ERROR_TYPES.FILE:
      return '📁';
    case ERROR_TYPES.SYSTEM:
      return '⚙️';
    case ERROR_TYPES.NETWORK:
      return '🌐';
    case ERROR_TYPES.ANALYSIS:
    default:
      return '⚠️';
  }
}

/**
 * Get error severity level
 * @param {string} code - Error code
 * @returns {'error'|'warning'|'info'} Severity level
 */
export function getErrorSeverity(code) {
  const criticalErrors = ['TSHARK_NOT_FOUND', 'PYTHON_NOT_FOUND', 'PYTHON_CRASHED'];
  const warningErrors = ['FILE_TOO_LARGE', 'ANALYSIS_TIMEOUT', 'ANALYSIS_NO_DATA'];
  
  if (criticalErrors.includes(code)) return 'error';
  if (warningErrors.includes(code)) return 'warning';
  return 'error';
}

export { ERROR_MESSAGES, ERROR_TYPES };
