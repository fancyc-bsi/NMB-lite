// src/api/nmbApi.js
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080/api';

// Create an axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for logging
apiClient.interceptors.request.use(
  (config) => {
    console.log('Making request to:', config.url);
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Response error:', error);
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      throw new Error(error.response.data.error || 'Server error occurred');
    } else if (error.request) {
      // The request was made but no response was received
      throw new Error('No response received from server');
    } else {
      // Something happened in setting up the request
      throw new Error('Error setting up request');
    }
  }
);

const nmbApi = {
  startScan: async (scanConfig) => {
    try {
      const response = await apiClient.post('/scan', scanConfig);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to start scan: ${error.message}`);
    }
  },

  getSupportedPlugins: async () => {
    try {
      const response = await apiClient.get('/supported-plugins');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get supported plugins: ${error.message}`);
    }
  },

  controlNessus: async (controlConfig) => {
    try {
      const response = await apiClient.post('/nessus-controller', controlConfig);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to control Nessus: ${error.message}`);
    }
  },
  
  // New methods for enhanced Nessus Controller
  getScans: async (host, user = 'bstg', pass = 'BulletH@x') => {
    try {
      const response = await apiClient.get(`/nessus/scans?host=${encodeURIComponent(host)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get scans: ${error.message}`);
    }
  },
  
  getScanDetail: async (scanId, host, user = 'bstg', pass = 'BulletH@x') => {
    try {
      const response = await apiClient.get(`/nessus/scan/${scanId}?host=${encodeURIComponent(host)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get scan details: ${error.message}`);
    }
  },
  
  controlScan: async (scanId, action, host, user = 'bstg', pass = 'BulletH@x') => {
    try {
      const response = await apiClient.post(`/nessus/scan/${scanId}/${action}?host=${encodeURIComponent(host)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to ${action} scan: ${error.message}`);
    }
  },
  
  // WebSocket connection management
  connectToWebSocket: (onMessage) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${wsProtocol}://${window.location.hostname}:8080/ws`;
    
    const socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
      console.log('WebSocket connection established');
      
      // Set up ping to keep connection alive
      const pingInterval = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send('ping');
        } else {
          clearInterval(pingInterval);
        }
      }, 30000);
    };
    
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };
    
    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    socket.onclose = (event) => {
      console.log('WebSocket connection closed:', event.code, event.reason);
      
      // Attempt to reconnect after a delay
      setTimeout(() => {
        console.log('Attempting to reconnect WebSocket...');
        nmbApi.connectToWebSocket(onMessage);
      }, 5000);
    };
    
    return socket;
  }
};

export default nmbApi;