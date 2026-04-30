'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getCredentials:  ()         => ipcRenderer.invoke('get-credentials'),
  saveCredentials: (creds)    => ipcRenderer.invoke('save-credentials', creds),
  getAccessToken:  (clientId) => ipcRenderer.invoke('get-access-token', clientId),
  signOut:         ()         => ipcRenderer.invoke('sign-out'),
});
