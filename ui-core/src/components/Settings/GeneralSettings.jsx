// src/components/Settings/GeneralSettings.jsx
import React, { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Grid,
  IconButton,
  InputAdornment,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
} from '@mui/material';
import { Save, Folder, Plus, Trash2, Edit2 } from 'lucide-react';

const GeneralSettings = () => {
  const [settings, setSettings] = useState({
    defaultProjectFolder: '/evidence',
    maxWorkers: 4,
    autoStart: true,
    telemetry: true,
    sshKeyFile: '',
    drones: [],
  });

  const [status, setStatus] = useState({
    open: false,
    message: '',
    severity: 'success'
  });

  const [droneDialog, setDroneDialog] = useState({
    open: false,
    mode: 'add',
    drone: { name: '', host: '', user: '' }
  });

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/settings');
        const data = await response.json();
        // Ensure drones is always an array
        setSettings({
          ...data,
          drones: data.drones || []  // Use empty array if drones is null/undefined
        });
      } catch (error) {
        showStatus('Error loading settings', 'error');
        // Set default settings on error
        setSettings(prev => ({
          ...prev,
          drones: []  // Ensure drones is an empty array
        }));
      }
    };
    loadSettings();
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleBrowseFile = async (type) => {
    try {
      let result;
      if (type === 'folder') {
        result = await window.go.main.App.SelectDirectory();
      } else {
        result = await window.go.main.App.SelectFile("All Files");
      }
  
      if (result) {
        const fieldMap = {
          folder: 'defaultProjectFolder',
          key: 'sshKeyFile'
        };
  
        setSettings(prev => ({
          ...prev,
          [fieldMap[type]]: result
        }));
      }
    } catch (error) {
      showStatus(`Error selecting ${type}: ${error.message}`, 'error');
    }
  };

  const showStatus = (message, severity = 'success') => {
    setStatus({
      open: true,
      message,
      severity
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8080/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings),
      });
      
      if (!response.ok) {
        throw new Error('Failed to save settings');
      }
      
      showStatus('Settings saved successfully');
      
      // Also save to localStorage for local access
      localStorage.setItem('nmb_settings', JSON.stringify(settings));
    } catch (error) {
      showStatus(error.message, 'error');
    }
  };

  const handleAddDrone = () => {
    setDroneDialog({
      open: true,
      mode: 'add',
      drone: { name: '', host: '', user: '' }
    });
  };

  const handleEditDrone = (drone, index) => {
    setDroneDialog({
      open: true,
      mode: 'edit',
      drone: { ...drone },
      index
    });
  };

  const handleDeleteDrone = (index) => {
    const newDrones = settings.drones.filter((_, i) => i !== index);
    setSettings(prev => ({ ...prev, drones: newDrones }));
    showStatus('Drone removed');
  };

  const handleSaveDrone = () => {
    const { mode, drone, index } = droneDialog;
    let newDrones = [...settings.drones];
    
    if (mode === 'add') {
      newDrones.push(drone);
    } else {
      newDrones[index] = drone;
    }
    
    setSettings(prev => ({ ...prev, drones: newDrones }));
    setDroneDialog(prev => ({ ...prev, open: false }));
    showStatus(`Drone ${mode === 'add' ? 'added' : 'updated'} successfully`);
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>General Settings</Typography>
      <form onSubmit={handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Default Project Folder"
              name="defaultProjectFolder"
              value={settings.defaultProjectFolder}
              onChange={handleChange}
              helperText="Base directory for all project files"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => handleBrowseFile('folder')}>
                      <Folder />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>

          <Grid item xs={12}>
            <TextField
              fullWidth
              label="SSH Key File"
              name="sshKeyFile"
              value={settings.sshKeyFile}
              onChange={handleChange}
              helperText="Default SSH key for remote connections"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => handleBrowseFile('key')}>
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
              type="number"
              label="Max Workers"
              name="maxWorkers"
              value={settings.maxWorkers}
              onChange={handleChange}
              helperText="Maximum number of concurrent workers"
              inputProps={{ min: 1, max: 32 }}
            />
          </Grid>

          {/* <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="subtitle1">Drones (Remote Connections)</Typography>
              <Button
                startIcon={<Plus />}
                onClick={handleAddDrone}
                variant="outlined"
                size="small"
              >
                Add Drone
              </Button>
            </Box>
            
            <List>
              {settings.drones.map((drone, index) => (
                <ListItem
                  key={index}
                  sx={{ 
                    bgcolor: 'background.paper',
                    mb: 1,
                    borderRadius: 1,
                    border: '1px solid',
                    borderColor: 'divider'
                  }}
                >
                  <ListItemText
                    primary={drone.name}
                    secondary={`${drone.user}@${drone.host}`}
                  />
                  <ListItemSecondaryAction>
                    <IconButton 
                      edge="end" 
                      onClick={() => handleEditDrone(drone, index)}
                      sx={{ mr: 1 }}
                    >
                      <Edit2 />
                    </IconButton>
                    <IconButton 
                      edge="end" 
                      onClick={() => handleDeleteDrone(index)}
                      color="error"
                    >
                      <Trash2 />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          </Grid> */}

          <Grid item xs={12}>
            <Button
              type="submit"
              variant="contained"
              startIcon={<Save />}
              sx={{ mt: 2 }}
            >
              Save Settings
            </Button>
          </Grid>
        </Grid>
      </form>

      {/* Drone Dialog */}
      <Dialog 
        open={droneDialog.open} 
        onClose={() => setDroneDialog(prev => ({ ...prev, open: false }))}
      >
        <DialogTitle>
          {droneDialog.mode === 'add' ? 'Add New Drone' : 'Edit Drone'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Drone Name"
                value={droneDialog.drone.name}
                onChange={(e) => setDroneDialog(prev => ({
                  ...prev,
                  drone: { ...prev.drone, name: e.target.value }
                }))}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Host"
                value={droneDialog.drone.host}
                onChange={(e) => setDroneDialog(prev => ({
                  ...prev,
                  drone: { ...prev.drone, host: e.target.value }
                }))}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="User"
                value={droneDialog.drone.user}
                onChange={(e) => setDroneDialog(prev => ({
                  ...prev,
                  drone: { ...prev.drone, user: e.target.value }
                }))}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button 
            onClick={() => setDroneDialog(prev => ({ ...prev, open: false }))}
          >
            Cancel
          </Button>
          <Button 
            onClick={handleSaveDrone} 
            variant="contained"
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

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
    </Paper>
  );
};

export default GeneralSettings; 