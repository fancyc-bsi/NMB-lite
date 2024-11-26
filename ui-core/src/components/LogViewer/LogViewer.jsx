import React, { useState, useEffect, useRef } from 'react';
import { Box, Paper, Typography, IconButton } from '@mui/material';
import { RotateCcw, Download, X } from 'lucide-react';

const LogViewer = () => {
  const [logs, setLogs] = useState([]);
  const [connected, setConnected] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const wsRef = useRef(null);
  const logContainerRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const pingIntervalRef = useRef(null);

  useEffect(() => {
    connectWebSocket();
    
    // Cleanup function
    return () => {
      cleanupWebSocket();
    };
  }, []); // Empty dependency array means this effect runs once on mount

  const cleanupWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
  };

  const connectWebSocket = () => {
    // Clean up any existing connection first
    cleanupWebSocket();

    try {
      console.log('Attempting to connect WebSocket...');
      const ws = new WebSocket('ws://localhost:8080/ws');
      
      ws.onopen = () => {
        console.log('WebSocket Connected');
        setConnected(true);
        setReconnectAttempt(0);
        
        // Set up ping interval
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 30000);
      };

      ws.onclose = (event) => {
        console.log('WebSocket Closed:', event);
        setConnected(false);
        
        // Only attempt to reconnect if this is still the current WebSocket
        if (wsRef.current === ws) {
          const timeout = Math.min(1000 * Math.pow(2, reconnectAttempt), 30000);
          console.log(`Attempting to reconnect in ${timeout}ms`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            setReconnectAttempt(prev => prev + 1);
            connectWebSocket();
          }, timeout);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket Error:', error);
        setConnected(false);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          setLogs(prev => [...prev, message]);
          
          // Auto-scroll to bottom
          if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
          }
        } catch (error) {
          console.error('Error parsing message:', error);
        }
      };

      // Store the WebSocket instance
      wsRef.current = ws;
    } catch (error) {
      console.error('Error creating WebSocket:', error);
      setConnected(false);
    }
  };

  // Rest of your component code remains the same...
  const getLogColor = (type) => {
    switch (type) {
      case 'error': return 'error.main';
      case 'warning': return 'warning.main';
      case 'success': return 'success.main';
      case 'info': return 'info.main';
      default: return 'text.primary';
    }
  };

  const clearLogs = () => setLogs([]);

  const downloadLogs = () => {
    const logText = logs.map(log => `[${log.time}] ${log.type.toUpperCase()}: ${log.message}`).join('\n');
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nmb-scan.log';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Return JSX remains the same...
  return (
    <Paper 
      elevation={3} 
      sx={{ 
        height: '400px', 
        display: 'flex', 
        flexDirection: 'column',
        m: 2 
      }}
    >
      <Box sx={{ 
        p: 1, 
        borderBottom: 1, 
        borderColor: 'divider',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <Typography variant="h6">
          Scan Logs
          <Box
            component="span"
            sx={{
              ml: 2,
              px: 1,
              py: 0.5,
              borderRadius: 1,
              backgroundColor: connected ? 'success.main' : 'error.main',
              color: 'white',
              fontSize: '0.75rem',
            }}
          >
            {connected ? 'CONNECTED' : 'DISCONNECTED'}
          </Box>
        </Typography>
        <Box>
          <IconButton onClick={clearLogs} size="small">
            <X size={18} />
          </IconButton>
          <IconButton onClick={connectWebSocket} size="small">
            <RotateCcw size={18} />
          </IconButton>
          <IconButton onClick={downloadLogs} size="small">
            <Download size={18} />
          </IconButton>
        </Box>
      </Box>
      
      <Box
        ref={logContainerRef}
        sx={{
          flex: 1,
          overflow: 'auto',
          p: 2,
          fontFamily: 'monospace',
          fontSize: '0.875rem',
          backgroundColor: 'background.default'
        }}
      >
        {logs.map((log, index) => (
          <Box 
            key={index} 
            sx={{ 
              color: getLogColor(log.type),
              py: 0.5
            }}
          >
            <Box component="span" sx={{ opacity: 0.7 }}>
              [{log.time}]
            </Box>{' '}
            {log.message}
          </Box>
        ))}
      </Box>
    </Paper>
  );
};

export default LogViewer;