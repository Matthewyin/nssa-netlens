const { app, BrowserWindow, ipcMain, dialog, Menu, clipboard, safeStorage } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const Store = require('electron-store');
const { OpenAI } = require('openai');

const store = new Store();

function encrypt(text) {
  if (!text) return '';
  if (!safeStorage.isEncryptionAvailable()) return text;
  try {
    return safeStorage.encryptString(text).toString('base64');
  } catch (e) {
    return text;
  }
}

function decrypt(text) {
  if (!text) return '';
  if (!safeStorage.isEncryptionAvailable()) return text;
  try {
    return safeStorage.decryptString(Buffer.from(text, 'base64'));
  } catch (e) {
    return text;
  }
}

const DEFAULT_WIDTH = 1400;
const DEFAULT_HEIGHT = 900;

// Initialize default settings
if (!store.get('outputDir')) {
  const documentsPath = app.getPath('documents');
  store.set('outputDir', path.join(documentsPath, 'MacPcapAnalyzer', 'Reports'));
}

// AI Settings & Migration
if (!store.get('aiProfiles')) {
  const oldConfig = store.get('aiConfig');
  const defaultProfile = {
    id: 'default',
    name: 'Default Profile',
    apiKey: oldConfig?.apiKey || '',
    baseUrl: oldConfig?.baseUrl || '',
    model: oldConfig?.model || ''
  };
  
  store.set('aiProfiles', [defaultProfile]);
  store.set('activeProfileId', 'default');
  store.delete('aiConfig');
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
  const rawProfiles = store.get('aiProfiles') || [];
  const profiles = rawProfiles.map(p => ({
      ...p,
      apiKey: decrypt(p.apiKey)
  }));

  return {
    outputDir: store.get('outputDir'),
    aiProfiles: profiles,
    activeProfileId: store.get('activeProfileId')
  };
});

ipcMain.handle('save-settings', (event, settings) => {
  if (settings.outputDir) store.set('outputDir', settings.outputDir);
  
  if (settings.aiProfiles) {
      const secureProfiles = settings.aiProfiles.map(p => ({
          ...p,
          apiKey: encrypt(p.apiKey)
      }));
      store.set('aiProfiles', secureProfiles);
  }
  
  if (settings.activeProfileId) store.set('activeProfileId', settings.activeProfileId);
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

// Helper to execute Python CLI
const handleAnalyzePcap = async (filePath, analysisType, searchQuery) => {
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
};

ipcMain.handle('analyze-pcap', async (event, filePath, analysisType, searchQuery) => {
  return await handleAnalyzePcap(filePath, analysisType, searchQuery);
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

ipcMain.handle('copy-to-clipboard', (event, text) => {
  clipboard.writeText(text);
  return true;
});

ipcMain.handle('verify-ai-config', async (event, config) => {
  try {
    if (!config.apiKey || !config.baseUrl || !config.model) {
      throw new Error('Missing configuration fields');
    }

    const openai = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseUrl,
    });

    await openai.chat.completions.create({
      model: config.model,
      messages: [{ role: 'user', content: 'Test' }],
      max_tokens: 1
    });

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('ask-ai', async (event, message, filePath) => {
  try {
    const rawProfiles = store.get('aiProfiles') || [];
    const profiles = rawProfiles.map(p => ({
        ...p,
        apiKey: decrypt(p.apiKey)
    }));
    
    const activeId = store.get('activeProfileId');
    const aiConfig = profiles.find(p => p.id === activeId);

    if (!aiConfig || !aiConfig.apiKey) {
      throw new Error('Active AI Profile not configured');
    }

    const openai = new OpenAI({
      apiKey: aiConfig.apiKey,
      baseURL: aiConfig.baseUrl,
    });

    const tools = [
      {
        type: "function",
        function: {
          name: "get_pcap_summary",
          description: "Get a high-level summary of the PCAP file including protocols and top talkers",
          parameters: {
            type: "object",
            properties: {
              filepath: { type: "string", description: "Path to the pcap file" }
            },
            required: ["filepath"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "scan_security_threats",
          description: "Scan the PCAP for security threats like SQLi, XSS, and port scans",
          parameters: {
            type: "object",
            properties: {
              filepath: { type: "string", description: "Path to the pcap file" }
            },
            required: ["filepath"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "analyze_tcp_anomalies",
          description: "Detect TCP anomalies like retransmissions, resets, and zero windows",
          parameters: {
            type: "object",
            properties: {
              filepath: { type: "string", description: "Path to the pcap file" }
            },
            required: ["filepath"]
          }
        }
      }
    ];

    const toolDefinitions = tools.map(t => ({
        name: t.function.name,
        description: t.function.description,
        parameters: t.function.parameters
    }));

    const systemPrompt = `You are NetLens AI, a specialized Network Packet Analysis Expert.
    Your goal is to help users understand, troubleshoot, and secure their network traffic by analyzing PCAP files.
    
    Current Analysis File: ${filePath || 'No file selected'}
    
    You have access to a powerful set of analysis tools (via Tshark backend).
    You can query summaries, inspect specific protocols (HTTP/DNS/TLS), diagnose TCP anomalies, and scan for security threats.
    
    [TOOL USE INSTRUCTIONS]
    You have the following tools available:
    ${JSON.stringify(toolDefinitions, null, 2)}

    To use a tool, you MUST strictly follow one of these formats:
    1. Native Function Calling (if supported by your model).
    2. JSON Block (Manual Fallback):
    \`\`\`json
    {
      "tool": "tool_name",
      "arguments": { "arg_name": "value" }
    }
    \`\`\`
    
    Guidelines:
    - Always base your analysis on REAL data retrieved from tools. Do not hallucinate packet details.
    - Be concise, professional, and data-driven.`;

    let messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: message }
    ];

    let response = await openai.chat.completions.create({
      model: aiConfig.model,
      messages: messages,
      tools: tools,
      tool_choice: "auto",
    });

    let responseMessage = response.choices[0].message;
    
    // Parser for manual tool calls (JSON or DSML)
    const extractToolCalls = (content) => {
        const calls = [];
        if (!content) return null;

        // 1. JSON Block
        const jsonMatch = content.match(/```json\s*(\{.*?\})\s*```/s);
        if (jsonMatch) {
            try {
                const data = JSON.parse(jsonMatch[1]);
                if (data.tool && data.arguments) {
                    calls.push({
                        id: 'call_' + Math.random().toString(36).substr(2, 9),
                        type: 'function',
                        function: {
                            name: data.tool,
                            arguments: JSON.stringify(data.arguments)
                        }
                    });
                }
            } catch (e) {}
        }
        
        // 2. DSML (DeepSeek XML)
        if (content.includes('<｜DSML｜invoke')) {
             const invokeRegex = /<｜DSML｜invoke name="([^"]+)">([\s\S]*?)<\/｜DSML｜invoke>/g;
             let match;
             while ((match = invokeRegex.exec(content)) !== null) {
                const name = match[1];
                const inner = match[2];
                const args = {};
                const paramRegex = /<｜DSML｜parameter name="([^"]+)"[^>]*>([\s\S]*?)<\/｜DSML｜parameter>/g;
                let pMatch;
                while ((pMatch = paramRegex.exec(inner)) !== null) {
                    args[pMatch[1]] = pMatch[2];
                }
                calls.push({
                    id: 'call_' + Math.random().toString(36).substr(2, 9),
                    type: 'function',
                    function: {
                        name: name,
                        arguments: JSON.stringify(args)
                    }
                });
             }
        }
        return calls.length > 0 ? calls : null;
    };

    let loopCount = 0;
    const MAX_LOOPS = 5;

    while (loopCount < MAX_LOOPS) {
        let toolCalls = responseMessage.tool_calls;
        if (!toolCalls) {
            toolCalls = extractToolCalls(responseMessage.content);
        }

        if (!toolCalls) {
            break;
        }

        if (!responseMessage.tool_calls) {
            if (responseMessage.content) {
                messages.push({ role: "assistant", content: responseMessage.content });
            }
        } else {
            messages.push(responseMessage);
        }

        for (const toolCall of toolCalls) {
            const functionName = toolCall.function.name;
            const functionArgs = JSON.parse(toolCall.function.arguments);
            
            console.log(`AI calling tool: ${functionName}`);
            
            let analysisType = functionName;
            if (functionName === 'get_pcap_summary') analysisType = 'pcap_summary';
            if (functionName === 'scan_security_threats') analysisType = 'security_scan';
            if (functionName === 'analyze_tcp_anomalies') analysisType = 'tcp_anomalies';

            const result = await handleAnalyzePcap(functionArgs.filepath || filePath, analysisType, "");
            
            if (responseMessage.tool_calls) {
                messages.push({
                  tool_call_id: toolCall.id,
                  role: "tool",
                  name: functionName,
                  content: JSON.stringify(result),
                });
            } else {
                messages.push({
                    role: "user",
                    content: `Tool '${functionName}' Output: ${JSON.stringify(result)}`
                });
            }
        }

        response = await openai.chat.completions.create({
            model: aiConfig.model,
            messages: messages,
            tools: tools,
            tool_choice: "auto"
        });
        responseMessage = response.choices[0].message;
        loopCount++;
    }

    return { content: responseMessage.content || "（AI 完成了操作，但未返回文本总结）" };
  } catch (err) {
    console.error('AI Error:', err);
    throw err;
  }
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
