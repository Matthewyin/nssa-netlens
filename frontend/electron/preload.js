const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  selectPcapFile: () => ipcRenderer.invoke('select-pcap-file'),
  analyzePcap: (filePath, analysisType, searchQuery) => ipcRenderer.invoke('analyze-pcap', filePath, analysisType, searchQuery),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  selectOutputDirectory: () => ipcRenderer.invoke('select-output-directory'),
  getPacketDetails: (filePath, frameNumber) => ipcRenderer.invoke('get-packet-details', filePath, frameNumber),
  analyzeCorrelation: (file1, file2) => ipcRenderer.invoke('analyze-correlation', file1, file2),
  analyzeLinkTrace: (file1, file2) => ipcRenderer.invoke('analyze-link-trace', file1, file2),
  getTcpStreamPackets: (filePath, streamId, page) => ipcRenderer.invoke('get-tcp-stream-packets', filePath, streamId, page),
  askAi: (message, filePath) => ipcRenderer.invoke('ask-ai', message, filePath),
  verifyAiConfig: (config) => ipcRenderer.invoke('verify-ai-config', config),
  copyToClipboard: (text) => ipcRenderer.invoke('copy-to-clipboard', text),
});
