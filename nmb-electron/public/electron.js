// public/electron.js
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const isDev = require('electron-is-dev');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadURL(
    isDev
      ? 'http://localhost:3000'
      : `file://${path.join(__dirname, '../build/index.html')}`
  );

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }
}

// Handle file selection
ipcMain.on('select-file', async (event) => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: [
        { name: 'Nessus Files', extensions: ['nessus'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });
    event.reply('select-file-reply', result.canceled ? null : result.filePaths[0]);
  } catch (error) {
    console.error('Error in select-file:', error);
    event.reply('select-file-reply', null);
  }
});

// Handle directory selection
ipcMain.on('select-directory', async (event) => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory']
    });
    event.reply('select-directory-reply', result.canceled ? null : result.filePaths[0]);
  } catch (error) {
    console.error('Error in select-directory:', error);
    event.reply('select-directory-reply', null);
  }
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});