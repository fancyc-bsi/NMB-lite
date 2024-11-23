import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Alert,
  Snackbar,
  IconButton,
  InputAdornment,
  Divider,
} from '@mui/material';
import { 
  Play, 
  Pause, 
  RefreshCw, 
  Upload, 
  Folder,
  MonitorUp,
  UploadCloud,
  Rocket
} from 'lucide-react';
import nmbApi from '../api/nmbApi';
import LogViewer from '../components/LogViewer/LogViewer';

const NessusControl = () => {
  const [controlData, setControlData] = useState({
    nessusMode: '',
    remoteHost: '',
    remoteUser: '',
    remotePass: '',
    projectName: '',
    targetsFile: '',
    projectFolder: '',
    excludeFile: '',
    discovery: false,
  });

  const [status, setStatus] = useState({ 
    open: false, 
    message: '', 
    severity: 'success' 
  });

  const [isLoading, setIsLoading] = useState(false);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setControlData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleBrowseFile = async (type) => {
    try {
      setIsLoading(true);
      
      if (!window.electron?.ipcRenderer) {
        throw new Error('Electron IPC not available');
      }

      const channel = type === 'project' ? 'select-directory' : 'select-file';
      window.electron.ipcRenderer.send(channel);
      
      const result = await new Promise((resolve) => {
        window.electron.ipcRenderer.once(`${channel}-reply`, (filePath) => {
          resolve(filePath);
        });
      });

      if (result) {
        const fieldMap = {
          targets: 'targetsFile',
          project: 'projectFolder',
          exclude: 'excludeFile'
        };

        setControlData(prev => ({
          ...prev,
          [fieldMap[type]]: result
        }));
      }
    } catch (error) {
      setStatus({
        open: true,
        message: `Error selecting file: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await nmbApi.controlNessus(controlData);
      setStatus({
        open: true,
        message: `Operation started: ${controlData.nessusMode}`,
        severity: 'success'
      });
    } catch (error) {
      setStatus({
        open: true,
        message: error.message,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const QuickActionButton = ({ mode, icon: Icon, color = "primary", label }) => (
    <Button
      variant="contained"
      color={color}
      startIcon={Icon && <Icon />}
      onClick={() => setControlData(prev => ({ ...prev, nessusMode: mode }))}
      disabled={isLoading}
    >
      {label}
    </Button>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3 }}>Nessus Controller</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Quick Actions</Typography>
            <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
              <QuickActionButton 
                mode="start" 
                icon={Play} 
                label="Start Scan" 
              />
              <QuickActionButton 
                mode="pause" 
                icon={Pause} 
                color="warning" 
                label="Pause Scan" 
              />
              <QuickActionButton 
                mode="resume" 
                icon={RefreshCw} 
                color="info" 
                label="Resume Scan" 
              />
            </Box>
            
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
              <QuickActionButton 
                mode="deploy" 
                icon={UploadCloud} 
                color="secondary" 
                label="Deploy" 
              />
              <QuickActionButton 
                mode="monitor" 
                icon={MonitorUp} 
                color="info" 
                label="Monitor" 
              />
              <QuickActionButton 
                mode="launch" 
                icon={Rocket} 
                color="success" 
                label="Launch" 
              />
            </Box>
            
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Mode</InputLabel>
              <Select
                name="nessusMode"
                value={controlData.nessusMode}
                onChange={handleChange}
                label="Mode"
              >
                <MenuItem value="start">Start</MenuItem>
                <MenuItem value="pause">Pause</MenuItem>
                <MenuItem value="resume">Resume</MenuItem>
                <MenuItem value="stop">Stop</MenuItem>
                <MenuItem value="deploy">Deploy</MenuItem>
                <MenuItem value="monitor">Monitor</MenuItem>
                <MenuItem value="create">Create</MenuItem>
                <MenuItem value="launch">Launch</MenuItem>
              </Select>
            </FormControl>

            <FormControlLabel
              control={
                <Switch
                  checked={controlData.discovery}
                  onChange={handleChange}
                  name="discovery"
                />
              }
              label="Discovery Mode"
            />
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Configuration</Typography>
            <form onSubmit={handleSubmit}>
              <TextField
                fullWidth
                margin="normal"
                label="Remote Host"
                name="remoteHost"
                value={controlData.remoteHost}
                onChange={handleChange}
              />
              
              <TextField
                fullWidth
                margin="normal"
                label="Remote User"
                name="remoteUser"
                value={controlData.remoteUser}
                onChange={handleChange}
              />
              
              <TextField
                fullWidth
                margin="normal"
                type="password"
                label="Remote Password"
                name="remotePass"
                value={controlData.remotePass}
                onChange={handleChange}
              />
              
              <TextField
                fullWidth
                margin="normal"
                label="Project Name"
                name="projectName"
                value={controlData.projectName}
                onChange={handleChange}
              />
              
              <TextField
                fullWidth
                margin="normal"
                label="Project Folder"
                name="projectFolder"
                value={controlData.projectFolder}
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
              
              <TextField
                fullWidth
                margin="normal"
                label="Targets File"
                name="targetsFile"
                value={controlData.targetsFile}
                onChange={handleChange}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton 
                        onClick={() => handleBrowseFile('targets')}
                        disabled={isLoading}
                      >
                        <Folder />
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
              
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                sx={{ mt: 2 }}
                startIcon={<Upload />}
                disabled={isLoading}
              >
                Apply Configuration
              </Button>
            </form>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <LogViewer />
        </Grid>
      </Grid>

      <Snackbar
        open={status.open}
        autoHideDuration={6000}
        onClose={() => setStatus(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          severity={status.severity} 
          sx={{ width: '100%' }}
          variant="filled"
        >
          {status.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default NessusControl;