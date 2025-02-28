import React, { useState, useEffect } from 'react';
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
  Autocomplete,
} from '@mui/material';
import { 
  Play, 
  Pause, 
  RefreshCw, 
  Upload, 
  Folder,
  MonitorUp,
  UploadCloud,
  Rocket,
  Save
} from 'lucide-react';
import nmbApi from '../api/nmbApi';
import LogViewer from '../components/LogViewer/LogViewer';


// Default credentials
const DEFAULT_CREDENTIALS = {
  username: 'bstg',
  password: 'BulletH@x'
};

// Drone list
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
  "pacman", "tetris", "sonic", "burgertime", "diablo", "lemmings", "quake", "myst",
  "fzero", "blasteroids", "outrun", "rampart", "castlevania", "ikari", "halo",
  "simcity", "warcraft", "starwars", "choplifter", "gunfight", "metroid",
  "ninjagaiden", "iceclimber", "icehockey", "radracer", "battletoads", "gradius",
  "ninjaturtles", "fdl-aws-1", "hrd-1", "rsi-aws-1", "evi-lite-1", "evi-lite-2",
  "hrd-lite-1", "trm-lite-1", "brain", "wily", "eggman", "ganon", "goro", "mantis",
  "sigma", "wario", "blinky", "goomba", "kefka", "bison", "bowser", "kingboo",
  "clyde", "mewtwo", "koopa", "akuma"
];

// Define field requirements for each mode
const MODE_FIELDS = {
  create: ['projectName', 'targetsFile'],
  deploy: ['projectName', 'targetsFile'],
  start: ['projectName'],
  stop: ['projectName'],
  pause: ['projectName'],
  resume: ['projectName'],
  monitor: ['projectName'],
  launch: ['projectName', 'targetsFile'],
};


// Field configurations
const FIELD_CONFIG = {
  projectName: {
    label: 'Project/Scan Name',
    type: 'text',
    required: true,
  },
  targetsFile: {
    label: 'Targets File',
    type: 'file',
    required: true,
    browsable: true,
  },
  remoteHost: {
    label: 'Remote Host',
    type: 'text',
    group: 'remote',
  },
  remoteUser: {
    label: 'Remote User',
    type: 'text',
    group: 'remote',
  },
  remotePass: {
    label: 'Remote Password',
    type: 'password',
    group: 'remote',
  },
  remoteKey: {
    label: 'SSH Key File',
    type: 'file',
    browsable: true,
    group: 'remote',
  },
  discovery: {
    label: 'Discovery Mode',
    type: 'switch',
  },
};

const NessusControl = () => {
  const [controlData, setControlData] = useState({
    nessusMode: '',
    remoteHost: '',
    remoteUser: '',
    remotePass: '',
    remoteKey: '',
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
  const [requiredFields, setRequiredFields] = useState([]);

  // Update required fields when mode changes
  useEffect(() => {
    if (controlData.nessusMode) {
      setRequiredFields(MODE_FIELDS[controlData.nessusMode] || []);
    }
  }, [controlData.nessusMode]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setControlData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleHostChange = (event, newValue) => {
    setControlData(prev => ({
      ...prev,
      remoteHost: newValue || '',
      remoteUser: newValue ? DEFAULT_CREDENTIALS.username : '',
      remotePass: newValue ? DEFAULT_CREDENTIALS.password : ''
    }));
  };

  const handleBrowseFile = async (type) => {
    try {
      setIsLoading(true);
      
      let result;
      // Call the appropriate Wails function based on type
      if (type === 'directory') {
        result = await window.go.main.App.SelectDirectory();
      } else if (type === 'key') {
        result = await window.go.main.App.SelectFile("SSH Key");
      } else {
        result = await window.go.main.App.SelectFile("All Files");
      }
  
      if (result) {
        const fieldMap = {
          file: 'targetsFile',
          directory: 'projectFolder',
          key: 'remoteKey'
        };
  
        setControlData(prev => ({
          ...prev,
          [fieldMap[type]]: result
        }));
      }
    } catch (error) {
      setStatus({
        open: true,
        message: `Error selecting ${type}: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const validateForm = () => {
    const errors = requiredFields
      .filter(field => !controlData[field])
      .map(field => `${FIELD_CONFIG[field].label} is required`);
    
    if (errors.length > 0) {
      throw new Error(errors.join('\n'));
    }
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      validateForm();
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

  const renderField = (fieldName) => {
    const config = FIELD_CONFIG[fieldName];
    if (!config) return null;

    switch (config.type) {
      case 'switch':
        return (
          <FormControlLabel
            control={
              <Switch
                checked={controlData[fieldName]}
                onChange={handleChange}
                name={fieldName}
                disabled={isLoading}
              />
            }
            label={config.label}
          />
        );

      case 'file':
        return (
          <TextField
            fullWidth
            margin="normal"
            label={config.label}
            name={fieldName}
            value={controlData[fieldName]}
            onChange={handleChange}
            required={config.required}
            InputProps={config.browsable ? {
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton 
                    onClick={() => handleBrowseFile(fieldName === 'remoteKey' ? 'key' : 'file')}
                    disabled={isLoading}
                  >
                    <Folder />
                  </IconButton>
                </InputAdornment>
              ),
            } : undefined}
          />
        );

      default:
        if (fieldName === 'remoteHost') {
          return (
            <Autocomplete
              fullWidth
              options={DRONE_LIST}
              value={controlData.remoteHost}
              onChange={handleHostChange}
              renderInput={(params) => (
                <TextField
                  {...params}
                  margin="normal"
                  label={config.label}
                  required={config.required}
                  placeholder="Search for a drone..."
                />
              )}
              freeSolo
              renderOption={(props, option) => (
                <Box component="li" {...props}>
                  <Typography variant="body1">{option}</Typography>
                </Box>
              )}
            />
          );
        }
        return (
          <TextField
            fullWidth
            margin="normal"
            label={config.label}
            name={fieldName}
            type={config.type}
            value={controlData[fieldName]}
            onChange={handleChange}
            required={config.required}
            disabled={isLoading || (fieldName === 'remoteUser' || fieldName === 'remotePass' ? !controlData.remoteHost : false)}
          />
        );
    }
  };

  const getVisibleFields = () => {
    if (!controlData.nessusMode) return [];
  
    let modeFields = [...(MODE_FIELDS[controlData.nessusMode] || [])];
  
    // Ensure discovery is visible but not required in deploy mode
    if (controlData.nessusMode === 'deploy' && !modeFields.includes('discovery')) {
      modeFields.push('discovery');
    }
  
    const remoteFields = ['remoteHost', 'remoteUser', 'remotePass', 'remoteKey'];
    return [...modeFields, ...remoteFields];
  };
  

  const renderFormFields = () => {
    const visibleFields = getVisibleFields();
    const remoteFields = visibleFields.filter(field => FIELD_CONFIG[field]?.group === 'remote');
    const otherFields = visibleFields.filter(field => FIELD_CONFIG[field]?.group !== 'remote');

    return (
      <>
        {otherFields.map(fieldName => (
          <Box key={fieldName} sx={{ mb: 2 }}>
            {renderField(fieldName)}
          </Box>
        ))}

        {remoteFields.length > 0 && (
          <>
            <Divider sx={{ my: 3 }} />
            <Typography variant="subtitle1" gutterBottom sx={{ mb: 2 }}>
              Remote Configuration
            </Typography>
            {remoteFields.map(fieldName => (
              <Box key={fieldName} sx={{ mb: 2 }}>
                {renderField(fieldName)}
              </Box>
            ))}
          </>
        )}
      </>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3 }}>Nessus Controller</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Quick Actions</Typography>
            <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
              <QuickActionButton mode="start" icon={Play} label="Start Scan" />
              <QuickActionButton mode="pause" icon={Pause} color="warning" label="Pause Scan" />
              <QuickActionButton mode="resume" icon={RefreshCw} color="info" label="Resume Scan" />
            </Box>
            
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
              <QuickActionButton mode="deploy" icon={UploadCloud} color="secondary" label="Deploy" />
              <QuickActionButton mode="monitor" icon={MonitorUp} color="info" label="Monitor" />
              <QuickActionButton mode="launch" icon={Rocket} color="success" label="Launch" />
            </Box>
            
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Mode</InputLabel>
              <Select
                name="nessusMode"
                value={controlData.nessusMode}
                onChange={handleChange}
                label="Mode"
              >
                <MenuItem value="create">Create</MenuItem>
                <MenuItem value="deploy">Deploy</MenuItem>
                <MenuItem value="start">Start</MenuItem>
                <MenuItem value="pause">Pause</MenuItem>
                <MenuItem value="resume">Resume</MenuItem>
                <MenuItem value="stop">Stop</MenuItem>
                <MenuItem value="monitor">Monitor</MenuItem>
                <MenuItem value="launch">Launch</MenuItem>
              </Select>
            </FormControl>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Configuration</Typography>
            <form onSubmit={handleSubmit}>
              {renderFormFields()}
              
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                sx={{ mt: 2 }}
                startIcon={<Save />}
                disabled={isLoading || !controlData.nessusMode}
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