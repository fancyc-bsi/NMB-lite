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
  Tabs,
  Tab,
  Card,
  CardContent,
  CardActions,
  Stepper,
  Step,
  StepLabel,
  CircularProgress,
  Chip,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
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
  Save,
  Plus,
  Search,
  FileDown,
  AlertTriangle,
  CheckCircle,
  Clock,
  StopCircle,
  Trash2,
  Download,
  FileSearch,
  HelpCircle,
  Settings,
  XCircle,
  MoreHorizontal
} from 'lucide-react';
import nmbApi from '../api/nmbApi';

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
  "pacman", "pendrone", "tetris", "sonic", "burgertime", "diablo", "lemmings", "quake", "myst",
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
    helperText: 'Enter a unique name using only letters, hyphens, and underscores (no spaces or numbers)',
    pattern: '^[a-zA-Z_-]+$',
    validateMessage: 'Only letters, hyphens, and underscores allowed',
  },
  targetsFile: {
    label: 'Targets File',
    type: 'file',
    required: true,
    browsable: true,
    helperText: 'Select a file containing target IPs or hostnames (one per line)',
  },
  remoteHost: {
    label: 'Remote Host',
    type: 'text',
    group: 'remote',
    helperText: 'The drone/server to run the scan from',
  },
  remoteUser: {
    label: 'Remote User',
    type: 'text',
    group: 'remote',
    helperText: 'Username for SSH connection',
  },
  remotePass: {
    label: 'Remote Password',
    type: 'password',
    group: 'remote',
    helperText: 'Password for SSH connection',
  },
  remoteKey: {
    label: 'SSH Key File',
    type: 'file',
    browsable: true,
    group: 'remote',
    helperText: 'Optional: SSH key file for authentication',
  },
  discovery: {
    label: 'Discovery Mode',
    type: 'switch',
    helperText: 'Run discovery scan before vulnerability scan',
  },
  projectFolder: {
    label: 'Project Folder',
    type: 'file',
    browsable: true,
    helperText: 'Folder to store scan results',
  },
};

// Scan statuses with color coding
const SCAN_STATUS = {
  running: { color: 'primary', icon: Play, label: 'Running' },
  completed: { color: 'success', icon: CheckCircle, label: 'Completed' },
  pending: { color: 'secondary', icon: Clock, label: 'Pending' },
  paused: { color: 'warning', icon: Pause, label: 'Paused' },
  failed: { color: 'error', icon: XCircle, label: 'Failed' },
  stopped: { color: 'error', icon: StopCircle, label: 'Stopped' },
};

const NessusControl = () => {
  // Tab management
  const [activeTab, setActiveTab] = useState(0);
  
  // Wizard steps for new scan
  const [activeStep, setActiveStep] = useState(0);
  const wizardSteps = ['Select Targets', 'Configure Scan', 'Review & Launch'];
  
  // Form data state
  const [controlData, setControlData] = useState({
    nessusMode: '',
    remoteHost: '',
    remoteUser: 'bstg',
    remotePass: 'BulletH@x',
    remoteKey: '',
    projectName: '',
    targetsFile: '',
    projectFolder: '',
    excludeFile: '',
    discovery: false,
  });

  // UI state
  const [status, setStatus] = useState({ 
    open: false, 
    message: '', 
    severity: 'success' 
  });
  const [isLoading, setIsLoading] = useState(false);
  const [requiredFields, setRequiredFields] = useState([]);
  const [websocket, setWebsocket] = useState(null);
  const [logMessages, setLogMessages] = useState([]);
  const [scanUpdates, setScanUpdates] = useState({});
  const [fieldErrors, setFieldErrors] = useState({});

  // Scans data
  const [existingScans, setExistingScans] = useState([]);

  const submitWithData = async (data) => {
    setIsLoading(true);
    try {
      // Validate the data we're about to submit
      if (!data.nessusMode) {
        throw new Error("Operation mode is required");
      }
      
      // Check required fields for the selected mode
      const modeFields = MODE_FIELDS[data.nessusMode] || [];
      const errors = modeFields
        .filter(field => !data[field])
        .map(field => `${FIELD_CONFIG[field].label} is required`);
      
      // Validate scan name if present
      if (data.projectName) {
        const nameRegex = /^[a-zA-Z_-]+$/;
        if (!nameRegex.test(data.projectName)) {
          errors.push("Project/Scan Name can only contain letters, hyphens, and underscores (no spaces, numbers or special characters)");
        }
      }
      
      if (errors.length > 0) {
        throw new Error(errors.join('\n'));
      }
      
      const response = await nmbApi.controlNessus(data);
      setStatus({
        open: true,
        message: `Operation started: ${data.nessusMode}`,
        severity: 'success'
      });
      
      // Reset wizard if in wizard mode
      if (activeTab === 1) {
        setActiveStep(0);
        setActiveTab(0); // Switch back to dashboard
      }
      
      // Refresh scans list after a delay
      setTimeout(() => {
        if (data.remoteHost) {
          fetchScans(data.remoteHost);
        }
      }, 2000);
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
  
  // WebSocket connection
  useEffect(() => {
    // Handle WebSocket messages
    const handleWebSocketMessage = (data) => {
      console.log('WebSocket message received:', data);
      
      if (data.type === 'scans_list') {
        try {
          const scans = JSON.parse(data.message);
          setExistingScans(scans);
        } catch (error) {
          console.error('Failed to parse scans list:', error);
        }
      } else if (data.type === 'scan_update') {
        // Update for a specific scan
        const parts = data.message.split(':');
        if (parts.length >= 2) {
          const scanId = parts[0].replace('Scan ', '').trim();
          setScanUpdates(prev => ({
            ...prev,
            [scanId]: data.message
          }));
        }
      } else if (data.type === 'scan_complete') {
        // Refresh scans when a scan is completed
        if (controlData.remoteHost) {
          fetchScans(controlData.remoteHost);
        }
      } else {
        // Add other log messages
        setLogMessages(prev => [...prev.slice(-99), data]);
      }
    };
    
    // Connect to WebSocket
    const ws = nmbApi.connectToWebSocket(handleWebSocketMessage);
    setWebsocket(ws);
    
    // Clean up WebSocket connection on unmount
    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, []);
  
  // Fetch scans when remote host changes
  useEffect(() => {
    if (controlData.remoteHost) {
      fetchScans(controlData.remoteHost);
    }
  }, [controlData.remoteHost]);
  
  // Function to fetch scans
  const fetchScans = async (host) => {
    if (!host) return;
    
    setIsLoading(true);
    try {
      const response = await nmbApi.getScans(
        host, 
        controlData.remoteUser, 
        controlData.remotePass
      );
      
      if (response && response.scans) {
        setExistingScans(response.scans);
      }
    } catch (error) {
      setStatus({
        open: true,
        message: `Error fetching scans: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Update required fields when mode changes
  useEffect(() => {
    if (controlData.nessusMode) {
      setRequiredFields(MODE_FIELDS[controlData.nessusMode] || []);
    }
  }, [controlData.nessusMode]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    const newValue = type === 'checkbox' ? checked : value;
    
    setControlData(prev => ({
      ...prev,
      [name]: newValue
    }));
    
    // Validate field if it has a pattern
    if (FIELD_CONFIG[name]?.pattern) {
      const pattern = new RegExp(FIELD_CONFIG[name].pattern);
      if (newValue && !pattern.test(newValue)) {
        setFieldErrors(prev => ({
          ...prev,
          [name]: FIELD_CONFIG[name].validateMessage || `Invalid format for ${FIELD_CONFIG[name].label}`
        }));
      } else {
        setFieldErrors(prev => {
          const newErrors = {...prev};
          delete newErrors[name];
          return newErrors;
        });
      }
    }
  };

  const handleHostChange = (event, newValue) => {
    setControlData(prev => ({
      ...prev,
      remoteHost: newValue || '',
      remoteUser: newValue ? DEFAULT_CREDENTIALS.username : '',
      remotePass: newValue ? DEFAULT_CREDENTIALS.password : ''
    }));
    
    // Clear existing scans when changing host
    setExistingScans([]);
    
    // Show loading indicator
    if (newValue) {
      setIsLoading(true);
      
      // Show status message
      setStatus({
        open: true,
        message: `Connecting to ${newValue}...`,
        severity: 'info'
      });
    }
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

  // Validate form fields
  const validateForm = () => {
    // Check required fields
    const errors = requiredFields
      .filter(field => !controlData[field])
      .map(field => `${FIELD_CONFIG[field].label} is required`);
    
    // Validate scan name if present
    if (controlData.projectName) {
      // Only allow letters, hyphens, and underscores, no spaces or special chars
      const nameRegex = /^[a-zA-Z_-]+$/;
      if (!nameRegex.test(controlData.projectName)) {
        errors.push("Project/Scan Name can only contain letters, hyphens, and underscores (no spaces, numbers or special characters)");
      }
    }
    
    if (errors.length > 0) {
      throw new Error(errors.join('\n'));
    }
    return true;
  };

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    
    // If nessusMode is empty and we're in the wizard tab, default to 'deploy'
    if (!controlData.nessusMode && activeTab === 1) {
      return submitWithData({
        ...controlData,
        nessusMode: 'deploy'
      });
    }
    
    // Otherwise, proceed with current controlData
    submitWithData(controlData);
  };

  const handleScanAction = async (scanId, action) => {
    if (!controlData.remoteHost) {
      setStatus({
        open: true,
        message: 'Please select a remote host first',
        severity: 'warning'
      });
      return;
    }
    
    setIsLoading(true);
    try {
      const response = await nmbApi.controlScan(
        scanId, 
        action, 
        controlData.remoteHost,
        controlData.remoteUser,
        controlData.remotePass
      );
      
      setStatus({
        open: true,
        message: response.message || `Scan ${action} operation successful`,
        severity: 'success'
      });
      
      // Refresh scans after a short delay
      setTimeout(() => {
        fetchScans(controlData.remoteHost);
      }, 1000);
      
    } catch (error) {
      setStatus({
        open: true,
        message: `Error performing ${action}: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportScan = async (scanId) => {
    if (!controlData.remoteHost) {
      setStatus({
        open: true,
        message: 'Please select a remote host first',
        severity: 'warning'
      });
      return;
    }
    
    setIsLoading(true);
    try {
      const response = await nmbApi.controlScan(
        scanId, 
        'export', 
        controlData.remoteHost,
        controlData.remoteUser,
        controlData.remotePass
      );
      
      setStatus({
        open: true,
        message: response.message || 'Scan export started. Files will be available in the project folder.',
        severity: 'success'
      });
    } catch (error) {
      setStatus({
        open: true,
        message: `Error exporting scan: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (!controlData.remoteHost) {
      setStatus({
        open: true,
        message: 'Please select a remote host first',
        severity: 'warning'
      });
      return;
    }
    
    if (!window.confirm('Are you sure you want to delete this scan? This action cannot be undone.')) {
      return;
    }
    
    setIsLoading(true);
    try {
      const response = await nmbApi.controlScan(
        scanId, 
        'delete', 
        controlData.remoteHost,
        controlData.remoteUser,
        controlData.remotePass
      );
      
      setStatus({
        open: true,
        message: response.message || 'Scan deleted successfully',
        severity: 'success'
      });
      
      // Refresh scans
      fetchScans(controlData.remoteHost);
      
    } catch (error) {
      setStatus({
        open: true,
        message: `Error deleting scan: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleNextStep = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBackStep = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleWizardComplete = () => {
    // Create updated data with the mode set
    const updatedData = {
      ...controlData,
      nessusMode: 'deploy'
    };
    
    // Use the updated data directly instead of waiting for state update
    submitWithData(updatedData);
  };

  const renderScanStatusChip = (status, progress) => {
    const statusConfig = SCAN_STATUS[status] || SCAN_STATUS.pending;
    const StatusIcon = statusConfig.icon;
    
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Chip 
          icon={<StatusIcon size={16} />}
          label={statusConfig.label}
          color={statusConfig.color}
          size="small"
        />
        {status === 'running' && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, ml: 1 }}>
            <LinearProgress 
              variant="determinate" 
              value={progress} 
              sx={{ width: 100 }} 
            />
            <Typography variant="body2">{progress}%</Typography>
          </Box>
        )}
      </Box>
    );
  };

  const renderSeverityIndicators = (findings) => {
    // Use placeholder data if real findings aren't available or to improve performance
    const placeholderFindings = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    // Use placeholder data instead of real findings
    const displayFindings = placeholderFindings;
    
    return (
      <Box sx={{ display: 'flex', gap: 0.5 }}>
        <Tooltip title={`Critical: ${displayFindings.critical}`}>
          <Chip 
            label={displayFindings.critical} 
            size="small" 
            sx={{ bgcolor: 'error.dark', color: 'white', minWidth: 40 }} 
          />
        </Tooltip>
        <Tooltip title={`High: ${displayFindings.high}`}>
          <Chip 
            label={displayFindings.high} 
            size="small" 
            sx={{ bgcolor: 'error.main', color: 'white', minWidth: 40 }} 
          />
        </Tooltip>
        <Tooltip title={`Medium: ${displayFindings.medium}`}>
          <Chip 
            label={displayFindings.medium} 
            size="small" 
            sx={{ bgcolor: 'warning.main', color: 'white', minWidth: 40 }} 
          />
        </Tooltip>
        <Tooltip title={`Low: ${displayFindings.low}`}>
          <Chip 
            label={displayFindings.low} 
            size="small" 
            sx={{ bgcolor: 'info.main', color: 'white', minWidth: 40 }} 
          />
        </Tooltip>
      </Box>
    );
  };

  const renderField = (fieldName) => {
    const config = FIELD_CONFIG[fieldName];
    if (!config) return null;

    const hasError = !!fieldErrors[fieldName];

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
            label={
              <Box>
                {config.label}
                {config.helperText && (
                  <Typography variant="caption" color="text.secondary" display="block">
                    {config.helperText}
                  </Typography>
                )}
              </Box>
            }
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
            helperText={config.helperText}
            InputProps={config.browsable ? {
              endAdornment: (
                <InputAdornment position="end">
                  <Tooltip title={`Browse for ${config.label}`}>
                    <IconButton 
                      onClick={() => handleBrowseFile(fieldName === 'remoteKey' ? 'key' : fieldName === 'projectFolder' ? 'directory' : 'file')}
                      disabled={isLoading}
                    >
                      <Folder />
                    </IconButton>
                  </Tooltip>
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
                  helperText={config.helperText}
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
            helperText={hasError ? fieldErrors[fieldName] : config.helperText}
            disabled={isLoading || (fieldName === 'remoteUser' || fieldName === 'remotePass' ? !controlData.remoteHost : false)}
            error={hasError}
            inputProps={config.pattern ? { pattern: config.pattern } : undefined}
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

  // Wizard steps content
  const renderWizardStep = (step) => {
    switch (step) {
      case 0: // Select Targets
        return (
          <Box>
            <Typography variant="h6" gutterBottom>Target Selection</Typography>
            <Typography variant="body2" paragraph>
              Define the scope of your vulnerability scan by selecting targets.
            </Typography>
            
            {renderField('projectName')}
            {renderField('targetsFile')}
            {renderField('discovery')}
            
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
              <Button 
                variant="contained" 
                onClick={handleNextStep} 
                disabled={!controlData.projectName || !controlData.targetsFile || Object.keys(fieldErrors).length > 0}
              >
                Next
              </Button>
            </Box>
          </Box>
        );
      
      case 1: // Configure Scan
        return (
          <Box>
            <Typography variant="h6" gutterBottom>Scan Configuration</Typography>
            <Typography variant="body2" paragraph>
              Configure how the scan will be executed.
            </Typography>
            
            {renderField('remoteHost')}
            {renderField('remoteUser')}
            {renderField('remotePass')}
            {renderField('remoteKey')}
            {renderField('projectFolder')}
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
              <Button onClick={handleBackStep}>Back</Button>
              <Button 
                variant="contained" 
                onClick={handleNextStep}
                disabled={!controlData.remoteHost}
              >
                Next
              </Button>
            </Box>
          </Box>
        );
      
      case 2: // Review & Launch
        return (
          <Box>
            <Typography variant="h6" gutterBottom>Review & Launch</Typography>
            <Typography variant="body2" paragraph>
              Review your scan configuration before launching.
            </Typography>
            
            <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
              <Table size="small">
                <TableBody>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold', width: '30%' }}>
                      Project Name
                    </TableCell>
                    <TableCell>{controlData.projectName}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Targets File
                    </TableCell>
                    <TableCell>{controlData.targetsFile}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Discovery Scan
                    </TableCell>
                    <TableCell>{controlData.discovery ? 'Enabled' : 'Disabled'}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Remote Host
                    </TableCell>
                    <TableCell>{controlData.remoteHost}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Remote User
                    </TableCell>
                    <TableCell>{controlData.remoteUser}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Project Folder
                    </TableCell>
                    <TableCell>{controlData.projectFolder || 'Default'}</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
              <Button onClick={handleBackStep}>Back</Button>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button 
                  variant="contained" 
                  color="primary"
                  startIcon={<Rocket />}
                  onClick={handleWizardComplete}
                  disabled={isLoading}
                >
                  Launch Scan
                </Button>
              </Box>
            </Box>
          </Box>
        );
      
      default:
        return null;
    }
  };

  // Dashboard content
  const renderDashboard = () => {
    return (
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">
            {controlData.remoteHost ? 
              `Scans on ${controlData.remoteHost}` : 
              'Select a host to view scans'}
          </Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button 
              variant="outlined" 
              startIcon={<RefreshCw />}
              onClick={() => fetchScans(controlData.remoteHost)}
              size="small"
              disabled={!controlData.remoteHost || isLoading}
            >
              Refresh
            </Button>
            <Button 
              variant="contained" 
              startIcon={<Plus />}
              onClick={() => setActiveTab(1)}
              size="small"
              disabled={!controlData.remoteHost}
            >
              New Scan
            </Button>
          </Box>
        </Box>
        
        {!controlData.remoteHost ? (
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="body1" color="text.secondary">
              Please select a remote host to view and manage scans.
            </Typography>
            {renderField('remoteHost')}
          </Paper>
        ) : existingScans.length === 0 ? (
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            {isLoading ? (
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                <CircularProgress size={40} />
                <Typography variant="body1">Loading scans...</Typography>
              </Box>
            ) : (
              <Typography variant="body1" color="text.secondary">
                No scans found. Click "New Scan" to create one.
              </Typography>
            )}
          </Paper>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table sx={{ minWidth: 650 }} size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {existingScans.map((scan) => (
                  <TableRow key={scan.id} sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                    <TableCell component="th" scope="row">
                      <Typography variant="body2" fontWeight="medium">{scan.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{scan.targets}</Typography>
                    </TableCell>
                    <TableCell>
                      {renderScanStatusChip(scan.status, scan.progress)}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{scan.createdAt}</Typography>
                      {scan.completedAt && (
                        <Typography variant="caption" color="text.secondary">
                          Completed: {scan.completedAt}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        {scan.status === 'running' && (
                          <Tooltip title="Pause Scan">
                            <IconButton 
                              size="small"
                              onClick={() => handleScanAction(scan.id, 'pause')}
                              color="warning"
                            >
                              <Pause size={18} />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {scan.status === 'paused' && (
                          <Tooltip title="Resume Scan">
                            <IconButton 
                              size="small"
                              onClick={() => handleScanAction(scan.id, 'resume')}
                              color="primary"
                            >
                              <Play size={18} />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {scan.status === 'pending' && (
                          <Tooltip title="Start Scan">
                            <IconButton 
                              size="small"
                              onClick={() => handleScanAction(scan.id, 'start')}
                              color="primary"
                            >
                              <Play size={18} />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {(scan.status === 'running' || scan.status === 'paused') && (
                          <Tooltip title="Stop Scan">
                            <IconButton 
                              size="small"
                              onClick={() => handleScanAction(scan.id, 'stop')}
                              color="error"
                            >
                              <StopCircle size={18} />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {scan.status === 'completed' && (
                          <Tooltip title="Export Results">
                            <IconButton 
                              size="small"
                              onClick={() => handleExportScan(scan.id)}
                              color="primary"
                            >
                              <Download size={18} />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        <Tooltip title="View Details">
                          <IconButton 
                            size="small"
                            onClick={() => {/* View scan details */}}
                          >
                            <FileSearch size={18} />
                          </IconButton>
                        </Tooltip>
                        
                        <Tooltip title="Delete Scan">
                          <IconButton 
                            size="small"
                            onClick={() => handleDeleteScan(scan.id)}
                            color="error"
                          >
                            <Trash2 size={18} />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
        
        <Box sx={{ mt: 4 }}>
          <Typography variant="h6" gutterBottom>Quick Actions</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Monitor Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Monitor progress of an existing scan
                  </Typography>
                </CardContent>
                <CardActions>
                  <Button 
                    startIcon={<MonitorUp />} 
                    fullWidth
                    onClick={() => {
                      setControlData(prev => ({ ...prev, nessusMode: 'monitor' }));
                      setActiveTab(2);
                    }}
                  >
                    Monitor
                  </Button>
                </CardActions>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Export Results
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Export results of a completed scan
                  </Typography>
                </CardContent>
                <CardActions>
                  <Button 
                    startIcon={<FileDown />}
                    fullWidth
                    onClick={() => {
                      setControlData(prev => ({ ...prev, nessusMode: 'export' }));
                      setActiveTab(2);
                    }}
                  >
                    Export
                  </Button>
                </CardActions>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Create Template
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Create a scan template without running
                  </Typography>
                </CardContent>
                <CardActions>
                  <Button 
                    startIcon={<Save />}
                    fullWidth
                    onClick={() => {
                      setControlData(prev => ({ ...prev, nessusMode: 'create' }));
                      setActiveTab(2);
                    }}
                  >
                    Create
                  </Button>
                </CardActions>
              </Card>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Settings
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Configure global scan settings
                  </Typography>
                </CardContent>
                <CardActions>
                  <Button 
                    startIcon={<Settings />}
                    fullWidth
                    onClick={() => {/* Open settings dialog */}}
                  >
                    Settings
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          </Grid>
        </Box>
      </Box>
    );
  };

  // Manual configuration form
  const renderManualConfig = () => {
    return (
      <Box>
        <Typography variant="h6" gutterBottom>Manual Configuration</Typography>
        <FormControl fullWidth sx={{ mb: 3 }}>
          <InputLabel>Operation Mode</InputLabel>
          <Select
            name="nessusMode"
            value={controlData.nessusMode}
            onChange={handleChange}
            label="Operation Mode"
          >
            <MenuItem value="create">Create Scan</MenuItem>
            <MenuItem value="deploy">Deploy & Run</MenuItem>
            <MenuItem value="start">Start Scan</MenuItem>
            <MenuItem value="pause">Pause Scan</MenuItem>
            <MenuItem value="resume">Resume Scan</MenuItem>
            <MenuItem value="stop">Stop Scan</MenuItem>
            <MenuItem value="monitor">Monitor Scan</MenuItem>
            <MenuItem value="launch">Launch Scan</MenuItem>
            <MenuItem value="export">Export Results</MenuItem>
          </Select>
        </FormControl>
        
        <form onSubmit={handleSubmit}>
          {renderFormFields()}
          
          <Button
            type="submit"
            variant="contained"
            color="primary"
            fullWidth
            sx={{ mt: 3 }}
            startIcon={<Save />}
            disabled={isLoading || !controlData.nessusMode || Object.keys(fieldErrors).length > 0}
          >
            Apply Configuration
          </Button>
        </form>
      </Box>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3 }}>Nessus Controller</Typography>
      
      <Paper sx={{ mb: 3 }}>
        <Tabs 
          value={activeTab} 
          onChange={(e, newValue) => setActiveTab(newValue)}
          variant="fullWidth"
        >
          <Tab label="Dashboard" icon={<MonitorUp />} iconPosition="start" />
          <Tab label="New Scan" icon={<Plus />} iconPosition="start" />
          <Tab label="Manual Config" icon={<Settings />} iconPosition="start" />
        </Tabs>
      </Paper>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={activeTab === 2 ? 6 : 12}>
          <Paper sx={{ p: 3 }}>
            {/* Tab content */}
            {activeTab === 0 && renderDashboard()}
            
            {activeTab === 1 && (
              <Box>
                <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
                  {wizardSteps.map((label) => (
                    <Step key={label}>
                      <StepLabel>{label}</StepLabel>
                    </Step>
                  ))}
                </Stepper>
                {renderWizardStep(activeStep)}
              </Box>
            )}
            
            {activeTab === 2 && renderManualConfig()}
          </Paper>
        </Grid>
        
        {activeTab === 2 && (
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Quick Reference</Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Mode</TableCell>
                      <TableCell>Description</TableCell>
                      <TableCell>Required Fields</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>Create</TableCell>
                      <TableCell>Create a scan without running it</TableCell>
                      <TableCell>Project Name, Targets File</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Deploy</TableCell>
                      <TableCell>Create and start a scan</TableCell>
                      <TableCell>Project Name, Targets File</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Start</TableCell>
                      <TableCell>Start an existing scan</TableCell>
                      <TableCell>Project Name</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Pause</TableCell>
                      <TableCell>Pause a running scan</TableCell>
                      <TableCell>Project Name</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Resume</TableCell>
                      <TableCell>Resume a paused scan</TableCell>
                      <TableCell>Project Name</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Monitor</TableCell>
                      <TableCell>Monitor progress of a scan</TableCell>
                      <TableCell>Project Name</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        )}

        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Logs</Typography>
            <Box sx={{ maxHeight: '300px', overflow: 'auto', bgcolor: 'background.paper', p: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', mb: 2 }}>
              {logMessages.length > 0 ? (
                logMessages.map((log, index) => (
                  <Box 
                    key={index} 
                    sx={{ 
                      mb: 0.5,
                      color: log.type === 'error' ? 'error.main' : 
                             log.type === 'success' ? 'success.main' : 
                             log.type === 'warning' ? 'warning.main' : 'text.primary'
                    }}
                  >
                    <Typography component="span" variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                      [{log.time}]
                    </Typography>
                    <Typography component="span" variant="body2">
                      {log.message}
                    </Typography>
                  </Box>
                ))
              ) : (
                <Typography variant="body2" color="text.secondary">No log messages yet</Typography>
              )}
            </Box>
          </Paper>
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
      
      {isLoading && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
          }}
        >
          <Paper sx={{ p: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
            <CircularProgress />
            <Typography>Processing your request...</Typography>
          </Paper>
        </Box>
      )}
    </Box>
  );
};

export default NessusControl;