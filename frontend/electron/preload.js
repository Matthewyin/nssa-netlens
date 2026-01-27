const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  selectPcapFile: () => ipcRenderer.invoke('select-pcap-file'),
  analyzePcap: (filePath, analysisType, searchQuery) => ipcRenderer.invoke('analyze-pcap', filePath, analysisType, searchQuery),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  selectOutputDirectory: () => ipcRenderer.invoke('select-output-directory'),
  getPacketDetails: (filePath, frameNumber) => ipcRenderer.invoke('get-packet-details', filePath, frameNumber),
  analyzeCorrelation: (file1, file2) => ipcRenderer.invoke('analyze-correlation', file1, file2),
});
