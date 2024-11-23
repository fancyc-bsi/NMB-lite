// public/preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
  ipcRenderer: {
    send: (channel) => {
      const validChannels = ['select-file', 'select-directory'];
      if (validChannels.includes(channel)) {
        ipcRenderer.send(channel);
      }
    },
    once: (channel, callback) => {
      const validChannels = ['select-file-reply', 'select-directory-reply'];
      if (validChannels.includes(channel)) {
        ipcRenderer.once(channel, (event, ...args) => callback(...args));
      }
    }
  }
});