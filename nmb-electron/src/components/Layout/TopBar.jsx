// src/components/TopBar.jsx
import React from 'react';
import {
  AppBar,
  Toolbar,
  IconButton,
  Box,
  styled,
} from '@mui/material';
import { Minus, Square, X } from 'lucide-react';

const WindowControls = styled(Box)({
  display: 'flex',
  gap: '8px',
  marginLeft: 'auto',
  WebkitAppRegion: 'no-drag',
});

const TopBar = () => {
  const handleMinimize = () => {
    window.electronAPI.minimize();
  };

  const handleMaximize = () => {
    window.electronAPI.maximize();
  };

  const handleClose = () => {
    window.electronAPI.close();
  };

  return (
    <AppBar 
      position="fixed" 
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        background: 'transparent',
        boxShadow: 'none',
        WebkitAppRegion: 'drag'
      }}
    >
      <Toolbar variant="dense">
        <WindowControls>
          <IconButton 
            size="small" 
            onClick={handleMinimize}
            sx={{ 
              '&:hover': { 
                backgroundColor: 'rgba(255, 255, 255, 0.1)' 
              } 
            }}
          >
            <Minus size={16} />
          </IconButton>
          <IconButton 
            size="small" 
            onClick={handleMaximize}
            sx={{ 
              '&:hover': { 
                backgroundColor: 'rgba(255, 255, 255, 0.1)' 
              } 
            }}
          >
            <Square size={16} />
          </IconButton>
          <IconButton 
            size="small" 
            onClick={handleClose}
            sx={{ 
              '&:hover': { 
                backgroundColor: 'rgba(255, 0, 0, 0.1)',
                color: 'error.main'
              } 
            }}
          >
            <X size={16} />
          </IconButton>
        </WindowControls>
      </Toolbar>
    </AppBar>
  );
};

export default TopBar;