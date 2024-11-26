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
  CircularProgress,
  Tooltip
} from '@mui/material';
import { Folder, Save, RotateCcw, Key } from 'lucide-react';
const nmbApi = (__dirname, 'api', 'nmbApi');


const SCAN_FORM_KEY = 'scanform_state';
const SETTINGS_KEY = 'nmb_settings';

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
    const savedState = localStorage.getItem(SCAN_FORM_KEY);
    return savedState ? JSON.parse(savedState) : initialState;
  });

  const [status, setStatus] = useState({
    open: false,
    message: '',
    severity: 'info'
  });

  const [isLoading, setIsLoading] = useState(false);

  // Load default SSH key from settings on mount
  useEffect(() => {
    try {
      const savedSettings = localStorage.getItem(SETTINGS_KEY);
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        if (settings.sshKeyFile && !formData.remoteKey) {
          setFormData(prev => ({
            ...prev,
            remoteKey: settings.sshKeyFile
          }));
        }
      }
    } catch (error) {
      console.error('Error loading SSH key from settings:', error);
    }
  }, []);

  // Save form data to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem(SCAN_FORM_KEY, JSON.stringify(formData));
  }, [formData]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const useDefaultSSHKey = () => {
    try {
      const savedSettings = localStorage.getItem(SETTINGS_KEY);
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        if (settings.sshKeyFile) {
          setFormData(prev => ({
            ...prev,
            remoteKey: settings.sshKeyFile
          }));
          showStatus('Default SSH key loaded', 'success');
        } else {
          showStatus('No default SSH key found in settings', 'warning');
        }
      }
    } catch (error) {
      showStatus('Error loading default SSH key', 'error');
    }
  };

  const handleBrowseFile = async (type) => {
    try {
      setIsLoading(true);
      
      let result;
      // Call the appropriate Wails function based on type
      if (type === 'project') {
        result = await window.go.main.App.SelectDirectory();
      } else if (type === 'key') {
        result = await window.go.main.App.SelectFile("SSH Key");
      } else {
        // For nessus files or other types
        result = await window.go.main.App.SelectFile("All Files");
      }
  
      if (result) {
        const fieldMap = {
          nessus: 'nessusFilePath',
          project: 'projectFolder',
          key: 'remoteKey'
        };
  
        setFormData(prev => ({
          ...prev,
          [fieldMap[type]]: result
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
            label="SSH Key File"
            name="remoteKey"
            value={formData.remoteKey}
            onChange={handleChange}
            disabled={!formData.remoteHost}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <Tooltip title="Browse for SSH key">
                    <IconButton 
                      onClick={() => handleBrowseFile('key')}
                      disabled={isLoading || !formData.remoteHost}
                      sx={{ mr: 1 }}
                    >
                      <Folder />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Use default SSH key">
                    <IconButton
                      onClick={useDefaultSSHKey}
                      disabled={isLoading || !formData.remoteHost}
                    >
                      <Key />
                    </IconButton>
                  </Tooltip>
                </InputAdornment>
              ),
            }}
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