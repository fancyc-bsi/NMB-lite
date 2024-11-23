import React, { useState } from 'react';
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
  Grid
} from '@mui/material';
import { Save } from 'lucide-react';

const GeneralSettings = () => {
  const [settings, setSettings] = useState({
    defaultProjectFolder: '/path/to/projects',
    maxWorkers: 4,
    autoStart: true,
    telemetry: true,
    backupEnabled: false,
    backupLocation: '',
  });

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    // Save settings logic here
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
            />
          </Grid>
          
          <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle1" gutterBottom>Application Settings</Typography>
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.autoStart}
                  onChange={handleChange}
                  name="autoStart"
                />
              }
              label="Auto-start with system"
            />
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.telemetry}
                  onChange={handleChange}
                  name="telemetry"
                />
              }
              label="Send anonymous usage data"
            />
          </Grid>
          
          <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle1" gutterBottom>Backup Settings</Typography>
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.backupEnabled}
                  onChange={handleChange}
                  name="backupEnabled"
                />
              }
              label="Enable automatic backups"
            />
            
            {settings.backupEnabled && (
              <TextField
                fullWidth
                sx={{ mt: 2 }}
                label="Backup Location"
                name="backupLocation"
                value={settings.backupLocation}
                onChange={handleChange}
                helperText="Directory for backup files"
              />
            )}
          </Grid>
          
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
    </Paper>
  );
};

export default GeneralSettings;