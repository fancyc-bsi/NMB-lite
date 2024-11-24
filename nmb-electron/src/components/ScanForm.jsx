import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  Paper,
  Typography,
  Alert,
  Snackbar,
  IconButton,
  InputAdornment,
  Divider,
  Grid,
  CircularProgress
} from '@mui/material';
import { Folder, Save, RotateCcw } from 'lucide-react';
import nmbApi from '../api/nmbApi';

// Storage key for form data
const STORAGE_KEY = 'scanform_state';

const ScanForm = () => {
  // Initial state with default values
  const initialState = {
    nessusFilePath: '',
    projectFolder: '',
    remoteHost: '',
    remoteUser: '',
    remotePass: '',
    remoteKey: '',
    numWorkers: 4,
    configFilePath: '',
    excludeFile: '',
    discovery: false,
  };

  const [formData, setFormData] = useState(() => {
    // Load saved state from localStorage on component mount
    const savedState = localStorage.getItem(STORAGE_KEY);
    return savedState ? JSON.parse(savedState) : initialState;
  });

  const [status, setStatus] = useState({
    open: false,
    message: '',
    severity: 'info'
  });

  const [isLoading, setIsLoading] = useState(false);

  // Save form data to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(formData));
  }, [formData]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  // File selection handler using window.electron API
  const handleBrowseFile = async (type) => {
    try {
      setIsLoading(true);
      
      if (!window.electron?.ipcRenderer) {
        throw new Error('Electron IPC not available');
      }

      const channel = type === 'nessus' ? 'select-file' : 'select-directory';
      
      // Send the request through IPC
      window.electron.ipcRenderer.send(channel);
      
      // Create a promise to handle the response
      const result = await new Promise((resolve) => {
        window.electron.ipcRenderer.once(`${channel}-reply`, (filePath) => {
          resolve(filePath);
        });
      });

      if (result) {
        setFormData(prev => ({
          ...prev,
          [type === 'nessus' ? 'nessusFilePath' : 'projectFolder']: result
        }));
      }
    } catch (error) {
      showStatus(`Error selecting ${type}: ${error.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const showStatus = (message, severity = 'info') => {
    setStatus({
      open: true,
      message,
      severity
    });
  };

  const handleCloseStatus = () => {
    setStatus(prev => ({ ...prev, open: false }));
  };

  const resetForm = () => {
    if (window.confirm('Are you sure you want to reset all fields?')) {
      setFormData(initialState);
      showStatus('Form has been reset', 'info');
    }
  };

  const validateForm = () => {
    const errors = [];
    if (!formData.nessusFilePath) errors.push('Nessus file path is required');
    if (!formData.projectFolder) errors.push('Project folder is required');
    if (formData.remoteHost && !formData.remoteUser) errors.push('Remote user is required when using remote host');
    if (formData.numWorkers < 1) errors.push('Number of workers must be at least 1');
    
    if (errors.length > 0) {
      throw new Error(errors.join('\n'));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    try {
      validateForm();
      await nmbApi.startScan(formData);
      showStatus('Scan started successfully', 'success');
    } catch (error) {
      showStatus(error.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, m: 2 }}>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h5">Start New Scan</Typography>
        <Box>
          <IconButton onClick={resetForm} title="Reset form">
            <RotateCcw />
          </IconButton>
        </Box>
      </Box>
      
      <Divider sx={{ mb: 3 }} />

      <Box component="form" onSubmit={handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <TextField
              required
              fullWidth
              label="Nessus File Path"
              name="nessusFilePath"
              value={formData.nessusFilePath}
              onChange={handleChange}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton 
                      onClick={() => handleBrowseFile('nessus')}
                      disabled={isLoading}
                    >
                      <Folder />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>

          <Grid item xs={12}>
            <TextField
              required
              fullWidth
              label="Project Folder"
              name="projectFolder"
              value={formData.projectFolder}
              onChange={handleChange}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton 
                      onClick={() => handleBrowseFile('project')}
                      disabled={isLoading}
                    >
                      <Folder />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Remote Host"
              name="remoteHost"
              value={formData.remoteHost}
              onChange={handleChange}
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Remote User"
              name="remoteUser"
              value={formData.remoteUser}
              onChange={handleChange}
              disabled={!formData.remoteHost}
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              type="password"
              label="Remote Password"
              name="remotePass"
              value={formData.remotePass}
              onChange={handleChange}
              disabled={!formData.remoteHost}
            />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              type="number"
              label="Number of Workers"
              name="numWorkers"
              value={formData.numWorkers}
              onChange={handleChange}
              inputProps={{ min: 1, max: 32 }}
            />
          </Grid>

          <Grid item xs={12}>
            <Button
              type="submit"
              variant="contained"
              color="primary"
              fullWidth
              disabled={isLoading}
              sx={{ 
                height: 48,
                display: 'flex',
                gap: 1 
              }}
            >
              {isLoading ? (
                <>
                  <CircularProgress size={24} color="inherit" />
                  Processing...
                </>
              ) : (
                <>
                  <Save size={20} />
                  Start Scan
                </>
              )}
            </Button>
          </Grid>
        </Grid>
      </Box>

      <Snackbar
        open={status.open}
        autoHideDuration={6000}
        onClose={handleCloseStatus}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleCloseStatus}
          severity={status.severity}
          variant="filled"
          sx={{ width: '100%' }}
        >
          {status.message}
        </Alert>
      </Snackbar>
    </Paper>
  );
};

export default ScanForm;