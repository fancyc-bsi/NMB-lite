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
  Tooltip,
  Autocomplete
} from '@mui/material';
import { Folder, Save, RotateCcw, Key } from 'lucide-react';
import nmbApi from '../api/nmbApi';

const SCAN_FORM_KEY = 'scanform_state';
const SETTINGS_KEY = 'nmb_settings';
const DRONE_LIST = [
  "arkanoid", "asteroids", "bagman", "barbarian", "breakout", "civilization",
  "contra", "crossbow", "defender", "digdug", "doom", "donkeykong", "duckhunt",
  "galaga", "gauntlet", "gravitar", "journey", "joust", "jumpman", "junglehunt",
  "kaboom", "karatechamp", "knockout", "kungfu", "megaman", "meltdown", "metalgear",
  "millipede", "paperboy", "pitfall", "poleposition", "pong", "pooyan", "popeye",
  "punchout", "qbert", "rampage", "sinistar", "spaceinvaders", "spyhunter",
  "streetfighter", "tempest", "tron", "wizardry", "beserk", "zaxxon", "zork",
  "doubledragon", "gorf", "ballblazer", "centipede", "combat", "hangon", "mario",
  "foodfight", "excitebike", "jinks", "zelda", "frogger", "battlezone", "freeway",
  "pacman", "pendrone", "tetris", "sonic", "burgertime", "diablo", "lemmings", "quake", "myst",
  "fzero", "blasteroids", "outrun", "rampart", "castlevania", "ikari", "halo",
  "simcity", "warcraft", "starwars", "choplifter", "gunfight", "metroid",
  "ninjagaiden", "iceclimber", "icehockey", "radracer", "battletoads", "gradius",
  "ninjaturtles", "fdl-aws-1", "hrd-1", "rsi-aws-1", "evi-lite-1", "evi-lite-2",
  "hrd-lite-1", "trm-lite-1", "brain", "wily", "eggman", "ganon", "goro", "mantis",
  "sigma", "wario", "blinky", "goomba", "kefka", "bison", "bowser", "kingboo",
  "clyde", "mewtwo", "koopa", "akuma"
];

// Default credentials
const DEFAULT_CREDENTIALS = {
  username: 'bstg',
  password: 'BulletH@x'
};

const ScanForm = () => {
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
    const savedState = localStorage.getItem(SCAN_FORM_KEY);
    return savedState ? JSON.parse(savedState) : initialState;
  });

  const [status, setStatus] = useState({
    open: false,
    message: '',
    severity: 'info'
  });

  const [isLoading, setIsLoading] = useState(false);

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

  useEffect(() => {
    localStorage.setItem(SCAN_FORM_KEY, JSON.stringify(formData));
  }, [formData]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === "numWorkers" ? Number(value) : (type === 'checkbox' ? checked : value)
    }));
  };
  

  const handleHostChange = (event, newValue) => {
    setFormData(prev => ({
      ...prev,
      remoteHost: newValue || '',
      remoteUser: newValue ? DEFAULT_CREDENTIALS.username : '',
      remotePass: newValue ? DEFAULT_CREDENTIALS.password : ''
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
      if (type === 'project') {
        result = await window.go.main.App.SelectDirectory();
      } else if (type === 'key') {
        result = await window.go.main.App.SelectFile("SSH Key");
      } else {
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
      const response = await nmbApi.startScan({
        ...formData,
        numWorkers: Number(formData.numWorkers)  // Converts to number 
      });
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
              label="Nessus CSV File Path"
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
              label="Output Folder Location"
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

          <Grid item xs={12}>
            <Autocomplete
              fullWidth
              options={DRONE_LIST}
              value={formData.remoteHost}
              onChange={handleHostChange}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Remote Host"
                  placeholder="Search for a drone..."
                  required={false}
                />
              )}
              freeSolo
              renderOption={(props, option) => (
                <Box component="li" {...props}>
                  <Typography variant="body1">{option}</Typography>
                </Box>
              )}
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