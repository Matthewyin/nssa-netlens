const { app, BrowserWindow, ipcMain, dialog, Menu } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const Store = require('electron-store');

const store = new Store();

const DEFAULT_WIDTH = 1400;
const DEFAULT_HEIGHT = 900;

// Initialize default settings
if (!store.get('outputDir')) {
  const documentsPath = app.getPath('documents');
  store.set('outputDir', path.join(documentsPath, 'MacPcapAnalyzer', 'Reports'));
}

let mainWindow;
let pythonProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: DEFAULT_WIDTH,
    height: DEFAULT_HEIGHT,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#F8FAFC'
  });

  const template = [
    {
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'pasteAndMatchStyle' },
        { role: 'delete' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        { type: 'separator' },
        { role: 'front' },
        { type: 'separator' },
        { role: 'window' }
      ]
    }
  ];
  
  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);

  const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
  
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

ipcMain.handle('select-pcap-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'PCAP Files', extensions: ['pcap', 'pcapng', 'cap'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });
  
  return result.filePaths;
});

ipcMain.handle('get-settings', () => {
  return {
    outputDir: store.get('outputDir')
  };
});

ipcMain.handle('save-settings', (event, settings) => {
  if (settings.outputDir) {
    store.set('outputDir', settings.outputDir);
  }
  return true;
});

ipcMain.handle('select-output-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory', 'createDirectory']
  });
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

ipcMain.handle('zoom', (event, delta) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (win) {
      const current = win.webContents.getZoomLevel();
      win.webContents.setZoomLevel(current + delta);
  }
});

ipcMain.handle('analyze-pcap', async (event, filePath, analysisType, searchQuery) => {
  return new Promise((resolve, reject) => {
    const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
    
    let pythonCmd;
    let args;
    
    if (isDev) {
      pythonCmd = 'uv';
      const pythonBackendPath = path.join(__dirname, '..', '..', 'backend');
      const outputDir = store.get('outputDir');
      args = [
        'run',
        '--directory',
        pythonBackendPath,
        'python',
        '-m',
        'pcap_analyzer.cli',
        analysisType,
        filePath,
        '--output-dir',
        outputDir || '',
        '--search',
        searchQuery || ''
      ];
    } else {
      pythonCmd = path.join(process.resourcesPath, 'python-backend', 'server');
      args = [analysisType, filePath];
    }

    const childProcess = spawn(pythonCmd, args);
    let stdout = '';
    let stderr = '';

    childProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    childProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    childProcess.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse JSON: ${e.message}`));
        }
      } else {
        reject(new Error(`Python process exited with code ${code}: ${stderr}`));
      }
    });
  });
});

ipcMain.handle('get-packet-details', async (event, filePath, frameNumber) => {
  return new Promise((resolve, reject) => {
    const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
    
    let pythonCmd;
    let args;
    
    if (isDev) {
      pythonCmd = 'uv';
      const pythonBackendPath = path.join(__dirname, '..', '..', 'backend');
      args = [
        'run',
        '--directory',
        pythonBackendPath,
        'python',
        '-m',
        'pcap_analyzer.cli',
        'packet_details',
        filePath,
        '--frame',
        frameNumber.toString()
      ];
    } else {
      pythonCmd = path.join(process.resourcesPath, 'python-backend', 'server');
      args = ['packet_details', filePath, '--frame', frameNumber.toString()];
    }

    const childProcess = spawn(pythonCmd, args);
    let stdout = '';
    let stderr = '';

    childProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    childProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    childProcess.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse JSON: ${e.message}`));
        }
      } else {
        reject(new Error(`Python process exited with code ${code}: ${stderr}`));
      }
    });
  });
});

ipcMain.handle('analyze-correlation', async (event, file1, file2) => {
  return new Promise((resolve, reject) => {
    const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
    
    let pythonCmd;
    let args;
    
    if (isDev) {
      pythonCmd = 'uv';
      const pythonBackendPath = path.join(__dirname, '..', '..', 'backend');
      args = [
        'run',
        '--directory',
        pythonBackendPath,
        'python',
        '-m',
        'pcap_analyzer.cli',
        'correlate',
        file1,
        '--file2',
        file2
      ];
    } else {
      pythonCmd = path.join(process.resourcesPath, 'python-backend', 'server');
      args = ['correlate', file1, '--file2', file2];
    }

    const childProcess = spawn(pythonCmd, args);
    let stdout = '';
    let stderr = '';

    childProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    childProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    childProcess.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse JSON: ${e.message}`));
        }
      } else {
        reject(new Error(`Python process exited with code ${code}: ${stderr}`));
      }
    });
  });
});

app.whenReady().then(() => {
  createWindow();
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
