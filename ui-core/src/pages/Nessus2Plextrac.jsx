import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Paper,
  Grid,
  MenuItem,
  FormControlLabel,
  Switch,
  Alert,
  CircularProgress,
  Tooltip,
  IconButton,
  InputAdornment,
  Snackbar,
  Divider,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Radio,
  RadioGroup,
  FormControl,
  FormLabel,
  List,
  ListItem,
  ListItemText,
  Tab,
  Tabs,
} from '@mui/material';
import {
  HelpOutline as HelpIcon,
  FolderOpen as FolderIcon,
  Upload as UploadIcon,
  Refresh as RefreshIcon,
  Check as CheckIcon,
  Error as ErrorIcon,
  Link as LinkIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugIcon,
  Add as AddIcon,
  AccountBalance as AccountBalanceIcon,
  Description as DescriptionIcon,
  Person as PersonIcon,
  LocationOn as LocationIcon,
} from '@mui/icons-material';

// Import Wails functions
import {
  RunN2P,
  CreateN2PClient,
  BrowseForNessusDirectory,
  BrowseForScreenshotDirectory,
  BrowseForClientConfig,
  GetPlextracServers,
  GetScopes,
  GetReportTemplates,
  GetFieldTemplates,
  CreateClientDetailed,
  CreateReportDetailed,
  GetFindings,
  UpdateFinding,
  BulkUpdateFindings,
} from '../wailsjs/go/main/App';

// Import FindingsTab component
import FindingsTab from './FindingsTab';

const Nessus2Plextrac = () => {
  // Add activeTab state
  const [activeTab, setActiveTab] = useState('config'); // Options: 'config', 'findings'
  
  // State for form fields
  const [config, setConfig] = useState({
    username: '',
    password: '',
    clientId: '',
    reportId: '',
    scope: 'internal',
    directory: '',
    targetPlextrac: 'report',
    screenshotDir: '',
    nonCore: false,
    clientConfig: '',
    overwrite: false,
    debug: false, // Added debug flag
  });

  // State for client creation dialog
  const [clientDialogOpen, setClientDialogOpen] = useState(false);
  const [clientCreationStep, setClientCreationStep] = useState(0);
  const [clientCreationData, setClientCreationData] = useState({
    projectCode: '',
    stateCode: '',
    clientName: '',
    reportTemplate: '',
    customFieldTemplate: '',
  });
  const [reportTemplates, setReportTemplates] = useState([]);
  const [customFieldTemplates, setCustomFieldTemplates] = useState([]);
  const [clientCreationErrors, setClientCreationErrors] = useState({});
  const [clientCreationLoading, setClientCreationLoading] = useState(false);
  const [clientCreationResult, setClientCreationResult] = useState({
    clientId: '',
    reportId: '',
    reportName: '',
    reportTemplateName: '',
    customFieldTemplateName: '',
    success: false,
  });

  // State for UI
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');
  const [logs, setLogs] = useState([]);
  const [plextracServers, setPlextracServers] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [errors, setErrors] = useState({});
  const [alert, setAlert] = useState({ open: false, message: '', severity: 'info' });
  const [reportUrl, setReportUrl] = useState('');
  const [debugInfo, setDebugInfo] = useState({
    lastRequest: null,
    lastResponse: null,
    lastError: null,
  });
  
  const logsEndRef = useRef(null);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const serverList = await GetPlextracServers();
        const scopeList = await GetScopes();
        setPlextracServers(serverList);
        setScopes(scopeList);
      } catch (error) {
        console.error('Failed to load initial data:', error);
        setAlert({
          open: true,
          message: 'Failed to load initial data. Please try again.',
          severity: 'error',
        });
      }
    };
    
    fetchData();
    
    // Set up event listeners
    window.runtime.EventsOn('n2p:status', (message) => {
      setStatus(message);
    });
    
    window.runtime.EventsOn('n2p:log', (logEntry) => {
      setLogs((prevLogs) => [...prevLogs, logEntry]);
    });
    
    // Setup debug event listeners
    window.runtime.EventsOn('n2p:debug', (debugData) => {
      setDebugInfo(prev => ({ 
        ...prev, 
        lastRequest: debugData.request || prev.lastRequest,
        lastResponse: debugData.response || prev.lastResponse,
        lastError: debugData.error || prev.lastError,
      }));
      
      // Also add to logs with debug level
      if (debugData) {
        setLogs(prevLogs => [...prevLogs, {
          time: new Date().toISOString(),
          level: 'debug',
          message: `Debug: ${JSON.stringify(debugData).substring(0, 200)}...`
        }]);
      }
    });
    
    return () => {
      window.runtime.EventsOff('n2p:status');
      window.runtime.EventsOff('n2p:log');
      window.runtime.EventsOff('n2p:debug');
    };
  }, []);

  // Load templates when opening client creation dialog
  useEffect(() => {
    if (clientDialogOpen && clientCreationStep === 3) {
      loadTemplates();
    }
  }, [clientDialogOpen, clientCreationStep]);

  // Auto-scroll logs to bottom when new logs arrive
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Load report and field templates
  const loadTemplates = async () => {
    try {
    setClientCreationLoading(true);
    
    // Check if credentials are available
    if (!config.username || !config.password) {
        setAlert({
        open: true,
        message: 'Username and password are required to fetch templates',
        severity: 'error',
        });
        setClientCreationLoading(false);
        return;
    }
    
    // Pass credentials to the template fetching functions
    const reportTemplatesData = await GetReportTemplates({
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac
    });
    
    const fieldTemplatesData = await GetFieldTemplates({
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac
    });
    
    setReportTemplates(reportTemplatesData);
    
    // Add "None" option to field templates
    setCustomFieldTemplates([
        ...fieldTemplatesData,
        { name: "None", value: "" }
    ]);
    
    setClientCreationLoading(false);
    } catch (error) {
    console.error('Failed to load templates:', error);
    setAlert({
        open: true,
        message: `Failed to load templates: ${error.message || 'Unknown error'}`,
        severity: 'error',
    });
    setClientCreationLoading(false);
    }
  };

  // Input change handler
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig({
      ...config,
      [name]: type === 'checkbox' ? checked : value,
    });
    
    // Clear validation error when field is edited
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: null,
      });
    }
  };

  // Client creation input change handler
  const handleClientCreationChange = (e) => {
    const { name, value } = e.target;
    setClientCreationData({
      ...clientCreationData,
      [name]: value,
    });
    
    // Clear validation error when field is edited
    if (clientCreationErrors[name]) {
      setClientCreationErrors({
        ...clientCreationErrors,
        [name]: null,
      });
    }
  };

  // Directory browsing handlers
  const handleBrowseNessusDirectory = async () => {
    try {
      const dir = await BrowseForNessusDirectory();
      if (dir) {
        setConfig({
          ...config,
          directory: dir,
        });
        setErrors({
          ...errors,
          directory: null,
        });
      }
    } catch (error) {
      console.error('Failed to browse for Nessus directory:', error);
      setAlert({
        open: true,
        message: 'Failed to browse for Nessus directory.',
        severity: 'error',
      });
    }
  };

  const handleBrowseScreenshotDirectory = async () => {
    try {
      const dir = await BrowseForScreenshotDirectory();
      if (dir) {
        setConfig({
          ...config,
          screenshotDir: dir,
        });
      }
    } catch (error) {
      console.error('Failed to browse for screenshot directory:', error);
      setAlert({
        open: true,
        message: 'Failed to browse for screenshot directory.',
        severity: 'error',
      });
    }
  };

  const handleBrowseClientConfig = async () => {
    try {
      const file = await BrowseForClientConfig();
      if (file) {
        setConfig({
          ...config,
          clientConfig: file,
        });
      }
    } catch (error) {
      console.error('Failed to browse for client config:', error);
      setAlert({
        open: true,
        message: 'Failed to browse for client configuration file.',
        severity: 'error',
      });
    }
  };

  // Validation function
  const validateForm = () => {
    const newErrors = {};
    
    if (!config.username) newErrors.username = 'Username is required';
    if (!config.password) newErrors.password = 'Password is required';
    if (!config.clientId) newErrors.clientId = 'Client ID is required';
    if (!config.reportId) newErrors.reportId = 'Report ID is required';
    if (!config.directory) newErrors.directory = 'Nessus directory is required';
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Validate client creation step
  const validateClientCreationStep = (step) => {
    const newErrors = {};
    
    switch (step) {
      case 0: // Project code step
        // Only validate that project code is not empty
        if (!clientCreationData.projectCode) {
          newErrors.projectCode = 'Project code is required';
        }
        break;
        
      case 1: // State code step
        if (!clientCreationData.stateCode) {
          newErrors.stateCode = 'State code is required';
        } else if (!/^[A-Z]{2}$/i.test(clientCreationData.stateCode)) {
          newErrors.stateCode = 'State code must be two letters';
        }
        break;
        
      case 2: // Client name step
        if (!clientCreationData.clientName) {
          newErrors.clientName = 'Client name is required';
        }
        break;
        
      case 3: // Template selection step
        if (!clientCreationData.reportTemplate) {
          newErrors.reportTemplate = 'Please select a report template';
        }
        break;
    }
    
    setClientCreationErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const prepareBackendConfig = (frontendConfig) => {
    // Create a new object with exact property names expected by Go backend
    return {
      username: frontendConfig.username,
      password: frontendConfig.password,
      clientId: frontendConfig.clientId,
      reportId: frontendConfig.reportId,
      scope: frontendConfig.scope,
      directory: frontendConfig.directory,
      targetPlextrac: frontendConfig.targetPlextrac,
      screenshotDir: frontendConfig.screenshotDir,
      nonCore: frontendConfig.nonCore,
      clientConfig: frontendConfig.clientConfig,
      overwrite: frontendConfig.overwrite
      // Explicitly exclude debug since it's not expected by backend
    };
  };

  const handleRunN2P = async () => {
    if (!validateForm()) return;
    
    setLoading(true);
    setLogs([]);
    setDebugInfo({lastRequest: null, lastResponse: null, lastError: null});
    setStatus('Initializing N2P process...');
    
    try {
      // Prepare config in format expected by backend
      const backendConfig = prepareBackendConfig(config);
      
      // For debugging - log what we're sending to the backend
      if (config.debug) {
        console.log('Sending to backend:', backendConfig);
        setLogs(prevLogs => [...prevLogs, {
          time: new Date().toISOString(),
          level: 'debug',
          message: `Sending to backend: ${JSON.stringify(backendConfig)}`
        }]);
      }
      
      const result = await RunN2P(backendConfig);
      
      // For debugging - log what we received from the backend
      if (config.debug) {
        console.log('Received from backend:', result);
        setLogs(prevLogs => [...prevLogs, {
          time: new Date().toISOString(),
          level: 'debug',
          message: `Received from backend: ${JSON.stringify(result)}`
        }]);
      }
      
      if (result.success === 'true') {
        setStatus(`N2P completed successfully in ${result.elapsedTime} seconds`);
        setAlert({
          open: true,
          message: `N2P completed successfully in ${result.elapsedTime} seconds`,
          severity: 'success',
        });
      } else {
        setStatus(`Error: ${result.errorMessage}`);
        setAlert({
          open: true,
          message: `Error: ${result.errorMessage}`,
          severity: 'error',
        });
        
        if (config.debug) {
          setDebugInfo(prev => ({
            ...prev,
            lastError: result.errorDetails || result.errorMessage
          }));
        }
      }
    } catch (error) {
      console.error('Error running N2P:', error);
      setStatus(`Error: ${error.message || 'Unknown error'}`);
      setAlert({
        open: true,
        message: `Error: ${error.message || 'Unknown error'}`,
        severity: 'error',
      });
      
      if (config.debug) {
        setDebugInfo(prev => ({
          ...prev,
          lastError: error
        }));
      }
    } finally {
      setLoading(false);
    }
  };
  
    // Fix for handleCreateClient function (simple version)
  const handleCreateClient = async () => {
    if (!config.username || !config.password || !config.targetPlextrac) {
      setErrors({
        ...errors,
        username: !config.username ? 'Username is required' : null,
        password: !config.password ? 'Password is required' : null,
      });
      return;
    }
    
    setLoading(true);
    setStatus('Creating client and report...');
    
    try {
      // Create a proper structure for the config object to pass to CreateN2PClient
      const clientConfig = {
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac
      };
      
      // Log what we're sending to verify it's correct
      console.log("Sending to CreateN2PClient:", clientConfig);
      
      const result = await CreateN2PClient(clientConfig);
      
      if (result.success === 'true') {
        setConfig({
          ...config,
          clientId: result.clientId,
          reportId: result.reportId,
        });
        setReportUrl(result.reportUrl);
        setStatus(`Client and report created successfully. Client ID: ${result.clientId}, Report ID: ${result.reportId}`);
        setAlert({
          open: true,
          message: `Client and report created successfully!`,
          severity: 'success',
        });
      } else {
        setStatus(`Error: ${result.error}`);
        setAlert({
          open: true,
          message: `Error: ${result.error}`,
          severity: 'error',
        });
      }
    } catch (error) {
      console.error('Error creating client and report:', error);
      setStatus(`Error: ${error.message || 'Unknown error'}`);
      setAlert({
        open: true,
        message: `Error: ${error.message || 'Unknown error'}`,
        severity: 'error',
      });
    } finally {
      setLoading(false);
    }
  };
  // Open advanced client creation dialog
  const handleOpenClientCreationDialog = () => {
    // Reset client creation state
    setClientCreationStep(0);
    setClientCreationData({
      projectCode: '',
      stateCode: '',
      clientName: '',
      reportTemplate: '',
      customFieldTemplate: '',
    });
    setClientCreationErrors({});
    setClientCreationResult({
      clientId: '',
      reportId: '',
      reportName: '',
      reportTemplateName: '',
      customFieldTemplateName: '',
      success: false,
    });
    setClientDialogOpen(true);
  };

  // Handle client creation steps
  const handleClientCreationNext = () => {
    if (validateClientCreationStep(clientCreationStep)) {
      if (clientCreationStep === 3) {
        // Final step - create client and report
        handleDetailedClientCreation();
      } else {
        setClientCreationStep(prevStep => prevStep + 1);
      }
    }
  };

  const handleClientCreationBack = () => {
    setClientCreationStep(prevStep => prevStep - 1);
  };

  const handleDetailedClientCreation = async () => {
    if (!config.username || !config.password || !config.targetPlextrac) {
      setAlert({
        open: true,
        message: 'Username, password and Plextrac server are required',
        severity: 'error',
      });
      return;
    }
    
    setClientCreationLoading(true);
    
    try {
      // Get the project code
      const projectCode = clientCreationData.projectCode.toUpperCase();
      const stateCode = clientCreationData.stateCode.toUpperCase();
      
      // Add to logs
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'info',
        message: `Creating client: ${clientCreationData.clientName} with code: ${projectCode}`
      }]);
      
      // Create client - Pass the credentials properly
      const clientResult = await CreateClientDetailed({
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac,
        clientName: clientCreationData.clientName,
        snPsCode: projectCode // Using the project code regardless of format
      });
      
      // Check for client creation success
      if (clientResult.success !== "true") {
        throw new Error(clientResult.error || 'Failed to create client');
      }
      
      // Add success log
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'success',
        message: `Client created with ID: ${clientResult.clientId}`
      }]);
      
      // Generate report name
      const reportName = `${projectCode}-${clientCreationData.clientName}-${stateCode}-Cybersecurity_Assessment-Draft-v1.0`;
      
      // Add to logs
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'info',
        message: `Creating report: ${reportName}`
      }]);
      
      // Create report - Pass the credentials properly
      const reportResult = await CreateReportDetailed({
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac,
        clientId: clientResult.clientId,
        reportName: reportName,
        reportTemplate: clientCreationData.reportTemplate,
        customFieldTemplate: clientCreationData.customFieldTemplate || ""
      });
      
      // Check for report creation success
      if (reportResult.success !== "true") {
        throw new Error(reportResult.error || 'Failed to create report');
      }
      
      // Add success log
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'success',
        message: `Report created with ID: ${reportResult.reportId}`
      }]);
      
      // Get template names
      const selectedReportTemplate = reportTemplates.find(t => t.value === clientCreationData.reportTemplate);
      const selectedFieldTemplate = customFieldTemplates.find(t => t.value === clientCreationData.customFieldTemplate);
      
      // Set result
      setClientCreationResult({
        clientId: clientResult.clientId,
        reportId: reportResult.reportId,
        reportName: reportName,
        reportTemplateName: selectedReportTemplate ? selectedReportTemplate.name : '',
        customFieldTemplateName: selectedFieldTemplate ? selectedFieldTemplate.name : 'None',
        success: true,
        reportUrl: reportResult.reportUrl
      });
      
      // Update main form
      setConfig({
        ...config,
        clientId: clientResult.clientId,
        reportId: reportResult.reportId,
      });
      
      setReportUrl(reportResult.reportUrl);
      
      // Set success message
      setStatus(`Client and report created successfully. Client ID: ${clientResult.clientId}, Report ID: ${reportResult.reportId}`);
      
      // Move to result step
      setClientCreationStep(4);
    } catch (error) {
      console.error('Error in client creation process:', error);
      
      // Add error log
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'error',
        message: `Client creation error: ${error.message || 'Unknown error'}`
      }]);
      
      setAlert({
        open: true,
        message: `Error: ${error.message || 'Unknown error'}`,
        severity: 'error',
      });
    } finally {
      setClientCreationLoading(false);
    }
  };

  // Close client creation dialog
  const handleCloseClientDialog = () => {
    setClientDialogOpen(false);
  };

  // Handle alert close
  const handleAlertClose = () => {
    setAlert({
      ...alert,
      open: false,
    });
  };

  // Clear logs
  const handleClearLogs = () => {
    setLogs([]);
    setDebugInfo({lastRequest: null, lastResponse: null, lastError: null});
  };

  // Get log level color
  const getLogLevelColor = (level) => {
    switch (level.toLowerCase()) {
      case 'debug':
        return '#8884d8';
      case 'info':
        return '#82ca9d';
      case 'warning':
        return '#ffc658';
      case 'error':
        return '#ff8042';
      case 'success':
        return '#4caf50';
      default:
        return '#82ca9d';
    }
  };

  // Format JSON for display
  const formatJSON = (json) => {
    try {
      if (typeof json === 'string') {
        return JSON.stringify(JSON.parse(json), null, 2);
      } else {
        return JSON.stringify(json, null, 2);
      }
    } catch (e) {
      return String(json);
    }
  };

  // Client creation dialog steps
  const clientCreationSteps = [
    {
      label: 'Project Code',
      icon: <AccountBalanceIcon />,
      content: (
        <Box sx={{ my: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Enter the project code
          </Typography>
          
          <TextField
            fullWidth
            label="Project Code"
            name="projectCode"
            value={clientCreationData.projectCode}
            onChange={handleClientCreationChange}
            error={!!clientCreationErrors.projectCode}
            helperText={clientCreationErrors.projectCode || "Enter the full project code (e.g., SN12345, PS01234, etc.)"}
            required
            placeholder="Enter project code"
          />
        </Box>
      ),
    },
    {
      label: 'State Code',
      icon: <LocationIcon />,
      content: (
        <Box sx={{ my: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Enter the two-letter state code
          </Typography>
          
          <TextField
            fullWidth
            label="State Code"
            name="stateCode"
            value={clientCreationData.stateCode}
            onChange={handleClientCreationChange}
            error={!!clientCreationErrors.stateCode}
            helperText={clientCreationErrors.stateCode || "Two-letter state abbreviation (e.g. CA, NY, TX)"}
            required
            inputProps={{ maxLength: 2 }}
            placeholder="CA"
          />
        </Box>
      ),
    },
    {
      label: 'Client Name',
      icon: <PersonIcon />,
      content: (
        <Box sx={{ my: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Enter the client name
          </Typography>
          
          <TextField
            fullWidth
            label="Client Name"
            name="clientName"
            value={clientCreationData.clientName}
            onChange={handleClientCreationChange}
            error={!!clientCreationErrors.clientName}
            helperText={clientCreationErrors.clientName}
            required
            placeholder="Acme Corporation"
          />
          
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            The full client name in Plextrac will be: {clientCreationData.clientName ? 
            `${clientCreationData.projectCode} - ${clientCreationData.clientName} - ${clientCreationData.stateCode}` : 
            '[Enter client name]'}
          </Typography>
        </Box>
      ),
    },
    {
      label: 'Templates',
      icon: <DescriptionIcon />,
      content: (
        <Box sx={{ my: 2 }}>
          <Typography variant="subtitle1" gutterBottom>
            Select report and custom field templates
          </Typography>
          
          {clientCreationLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <>
              <TextField
                select
                fullWidth
                label="Report Template"
                name="reportTemplate"
                value={clientCreationData.reportTemplate}
                onChange={handleClientCreationChange}
                error={!!clientCreationErrors.reportTemplate}
                helperText={clientCreationErrors.reportTemplate}
                required
                sx={{ mb: 2 }}
              >
                {reportTemplates.map((template) => (
                  <MenuItem key={template.value} value={template.value}>
                    {template.name}
                  </MenuItem>
                ))}
              </TextField>
              
              <TextField
                select
                fullWidth
                label="Custom Field Template"
                name="customFieldTemplate"
                value={clientCreationData.customFieldTemplate}
                onChange={handleClientCreationChange}
                helperText="Optional custom field template"
              >
                {customFieldTemplates.map((template) => (
                  <MenuItem key={template.value || 'none'} value={template.value}>
                    {template.name}
                  </MenuItem>
                ))}
              </TextField>
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                The report name will be: {`${clientCreationData.projectCode}-${clientCreationData.clientName}-${clientCreationData.stateCode}-Cybersecurity_Assessment-Draft-v1.0`}
              </Typography>
            </>
          )}
        </Box>
      ),
    },
    {
      label: 'Result',
      content: (
        <Box sx={{ my: 2 }}>
          <Typography variant="h6" gutterBottom color="success.main" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CheckIcon /> Success
          </Typography>
          
          <Typography variant="body1" gutterBottom>
            Client and report have been created successfully!
          </Typography>
          
          <Card variant="outlined" sx={{ mt: 2, mb: 3 }}>
            <CardContent>
              <List dense>
                <ListItem>
                  <ListItemText primary="Client ID" secondary={clientCreationResult.clientId} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Report ID" secondary={clientCreationResult.reportId} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Report Name" secondary={clientCreationResult.reportName} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Report Template" secondary={clientCreationResult.reportTemplateName} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Custom Field Template" secondary={clientCreationResult.customFieldTemplateName} />
                </ListItem>
              </List>
            </CardContent>
          </Card>
          
          {clientCreationResult.reportUrl && (
            <Button 
              variant="contained" 
              color="primary"
              startIcon={<LinkIcon />}
              href={clientCreationResult.reportUrl}
              target="_blank"
              fullWidth
            >
              Open Report in Plextrac
            </Button>
          )}
        </Box>
      ),
    },
  ];

  return (
    <Box sx={{ p: 3, maxWidth: '100%' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom sx={{ color: 'primary.main' }}>
            Nessus2Plextrac
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {config.debug && (
            <Chip 
              icon={<BugIcon />} 
              label="Debug Mode" 
              color="warning" 
              variant="outlined" 
              size="small"
            />
          )}
          
          {reportUrl && (
            <Button 
              variant="outlined" 
              color="primary"
              startIcon={<LinkIcon />}
              href={reportUrl}
              target="_blank"
              sx={{ height: 'fit-content' }}
            >
              Open Report
            </Button>
          )}
        </Box>
      </Box>

      {/* Tab Navigation */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs 
          value={activeTab} 
          onChange={(e, newValue) => setActiveTab(newValue)}
          aria-label="Nessus2Plextrac tabs"
        >
          <Tab label="Configuration" value="config" />
          <Tab 
            label="Findings Management" 
            value="findings" 
            disabled={!config.clientId || !config.reportId} 
          />
        </Tabs>
      </Box>

      {/* Conditional rendering based on active tab */}
      {activeTab === 'config' ? (
        <Grid container spacing={3}>
          {/* Form Section */}
          <Grid item xs={12} md={6}>
            <Paper
              elevation={3}
              sx={{
                p: 3,
                borderRadius: 2,
                height: '100%',
              }}
            >
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: 'primary.main', fontWeight: 'medium' }}>
                  Configuration
                </Typography>
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.debug}
                      onChange={handleChange}
                      name="debug"
                      color="warning"
                      size="small"
                    />
                  }
                  label={
                    <Box display="flex" alignItems="center">
                      <Typography variant="body2">Debug Mode</Typography>
                      <Tooltip title="Enable detailed debugging information">
                        <IconButton size="small">
                          <BugIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  }
                />
              </Box>
              <Divider sx={{ mb: 2 }} />

              <Grid container spacing={2}>
                {/* Authentication Section */}
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                    Authentication
                  </Typography>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Username"
                    name="username"
                    value={config.username}
                    onChange={handleChange}
                    error={!!errors.username}
                    helperText={errors.username}
                    required
                    size="small"
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Password"
                    name="password"
                    type="password"
                    value={config.password}
                    onChange={handleChange}
                    error={!!errors.password}
                    helperText={errors.password}
                    required
                    size="small"
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    select
                    label="Plextrac Server"
                    name="targetPlextrac"
                    value={config.targetPlextrac}
                    onChange={handleChange}
                    required
                    size="small"
                  >
                    {plextracServers.map((server) => (
                      <MenuItem key={server} value={server}>
                        {server}
                      </MenuItem>
                    ))}
                  </TextField>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Button
                    variant="outlined"
                    color="primary"
                    onClick={handleOpenClientCreationDialog}
                    disabled={loading || !config.username || !config.password || !config.targetPlextrac}
                    startIcon={<AddIcon />}
                    sx={{ mt: 0.5, height: '40px' }}
                    fullWidth
                  >
                    Client and Report Creation
                  </Button>
                </Grid>

                {/* Report Section */}
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="medium" gutterBottom sx={{ mt: 2 }}>
                    Report Details
                  </Typography>
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Client ID"
                    name="clientId"
                    value={config.clientId}
                    onChange={handleChange}
                    error={!!errors.clientId}
                    helperText={errors.clientId}
                    required
                    size="small"
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Report ID"
                    name="reportId"
                    value={config.reportId}
                    onChange={handleChange}
                    error={!!errors.reportId}
                    helperText={errors.reportId}
                    required
                    size="small"
                  />
                </Grid>

                {/* Import Settings */}
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="medium" gutterBottom sx={{ mt: 2 }}>
                    Import Settings
                  </Typography>
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    select
                    label="Scope"
                    name="scope"
                    value={config.scope}
                    onChange={handleChange}
                    required
                    helperText="Determines the tagging and title prefix"
                    size="small"
                  >
                    {scopes.map((scope) => (
                      <MenuItem key={scope.value} value={scope.value}>
                        {scope.label}
                      </MenuItem>
                    ))}
                  </TextField>
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.nonCore}
                        onChange={handleChange}
                        name="nonCore"
                        color="primary"
                      />
                    }
                    label={
                      <Box display="flex" alignItems="center">
                        <Typography>Add Non-Core Fields</Typography>
                        <Tooltip title="Add additional custom fields to the imported findings">
                          <IconButton size="small">
                            <HelpIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    }
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.overwrite}
                        onChange={handleChange}
                        name="overwrite"
                        color="primary"
                      />
                    }
                    label={
                      <Box display="flex" alignItems="center">
                        <Typography>Overwrite Existing Data</Typography>
                        <Tooltip title="Overwrite existing data in findings instead of appending">
                          <IconButton size="small">
                            <HelpIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    }
                  />
                </Grid>

                {/* Directory Paths */}
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="medium" gutterBottom sx={{ mt: 2 }}>
                    Files & Directories
                  </Typography>
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Nessus Directory"
                    name="directory"
                    value={config.directory}
                    onChange={handleChange}
                    required
                    error={!!errors.directory}
                    helperText={errors.directory || "Directory containing Nessus CSV files"}
                    size="small"
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleBrowseNessusDirectory} edge="end">
                            <FolderIcon />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Screenshot Directory (Optional)"
                    name="screenshotDir"
                    value={config.screenshotDir}
                    onChange={handleChange}
                    helperText="Directory containing screenshot images"
                    size="small"
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleBrowseScreenshotDirectory} edge="end">
                            <FolderIcon />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Client Config (Optional)"
                    name="clientConfig"
                    value={config.clientConfig}
                    onChange={handleChange}
                    helperText="TOML file with client-specific configurations"
                    size="small"
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleBrowseClientConfig} edge="end">
                            <FolderIcon />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>

                {/* Submit Button */}
                <Grid item xs={12}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={handleRunN2P}
                    disabled={loading}
                    startIcon={loading ? <CircularProgress size={20} /> : <UploadIcon />}
                    fullWidth
                    sx={{ mt: 2, py: 1 }}
                  >
                    {loading ? 'Processing...' : 'Run Nessus to Plextrac'}
                  </Button>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          {/* Status & Logs Section */}
          <Grid item xs={12} md={6}>
            <Paper
              elevation={3}
              sx={{
                p: 3,
                borderRadius: 2,
                display: 'flex',
                flexDirection: 'column',
                height: '100%',
              }}
            >
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  mb: 2,
                }}
              >
                <Typography variant="h6" sx={{ color: 'primary.main', fontWeight: 'medium' }}>
                  Status & Logs
                </Typography>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<RefreshIcon />}
                  onClick={handleClearLogs}
                >
                  Clear Logs
                </Button>
              </Box>
              <Divider sx={{ mb: 2 }} />

              {/* Status Box */}
              <Card 
                variant="outlined" 
                sx={{ 
                  mb: 2, 
                  backgroundColor: status.toLowerCase().includes('error') 
                    ? 'rgba(211, 47, 47, 0.04)' 
                    : status.toLowerCase().includes('success') 
                      ? 'rgba(76, 175, 80, 0.04)' 
                      : 'background.paper',
                  borderColor: status.toLowerCase().includes('error') 
                    ? 'error.main' 
                    : status.toLowerCase().includes('success') 
                      ? 'success.main' 
                      : 'divider'
                }}
              >
                <CardContent>
                  <Typography variant="caption" color="text.secondary" gutterBottom>
                    CURRENT STATUS
                  </Typography>
                  <Typography
                    variant="body1"
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      fontWeight: 'medium',
                    }}
                  >
                    {loading ? (
                      <CircularProgress size={16} />
                    ) : status.toLowerCase().includes('error') ? (
                      <ErrorIcon color="error" fontSize="small" />
                    ) : status ? (
                      <CheckIcon color="success" fontSize="small" />
                    ) : null}
                    {status || 'Ready to process'}
                  </Typography>
                </CardContent>
              </Card>

              {/* Debug Information */}
              {config.debug && (
                <Accordion 
                  sx={{ mb: 2, backgroundColor: 'rgba(236, 236, 236, 0.1)' }}
                  variant="outlined"
                >
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    aria-controls="debug-panel-content"
                    id="debug-panel-header"
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <BugIcon fontSize="small" color="warning" />
                      <Typography variant="subtitle2">Debug Information</Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ maxHeight: '200px', overflow: 'auto', fontSize: '0.75rem' }}>
                      {(!debugInfo.lastRequest && !debugInfo.lastResponse && !debugInfo.lastError) ? (
                        <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                          No debug information available yet. Start a process with debug mode enabled.
                        </Typography>
                      ) : (
                        <Box>
                          {debugInfo.lastError && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" color="error" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                                Last Error:
                              </Typography>
                              <Paper variant="outlined" sx={{ p: 1, backgroundColor: 'rgba(211, 47, 47, 0.04)' }}>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                  {formatJSON(debugInfo.lastError)}
                                </pre>
                              </Paper>
                            </Box>
                          )}
                          
                          {debugInfo.lastRequest && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                                Last Request:
                              </Typography>
                              <Paper variant="outlined" sx={{ p: 1 }}>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                  {formatJSON(debugInfo.lastRequest)}
                                </pre>
                              </Paper>
                            </Box>
                          )}
                          
                          {debugInfo.lastResponse && (
                            <Box>
                              <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                                Last Response:
                              </Typography>
                              <Paper variant="outlined" sx={{ p: 1 }}>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                  {formatJSON(debugInfo.lastResponse)}
                                </pre>
                              </Paper>
                            </Box>
                          )}
                        </Box>
                      )}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Log Display */}
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="subtitle2" fontWeight="medium">
                  Process Logs
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {logs.length} entries
                </Typography>
              </Box>
              
              <Paper
                variant="outlined"
                sx={{
                  backgroundColor: 'background.default',
                  borderRadius: 1,
                  flexGrow: 1,
                  overflow: 'auto',
                  maxHeight: '400px',
                  fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                  fontSize: '0.75rem',
                  padding: 0,
                }}
              >
                <Box sx={{ p: 1 }}>
                  {logs.length === 0 ? (
                    <Typography
                      variant="body2"
                      color="text.disabled"
                      sx={{ fontStyle: 'italic', p: 1, textAlign: 'center' }}
                    >
                      No logs yet. Start the process to see logs here.
                    </Typography>
                  ) : (
                    logs.map((log, index) => (
                      <Box
                        key={index}
                        sx={{
                          p: 0.75,
                          borderRadius: 1,
                          backgroundColor:
                            log.level === 'error'
                              ? 'rgba(255, 0, 0, 0.05)'
                              : log.level === 'warning'
                              ? 'rgba(255, 255, 0, 0.05)'
                              : log.level === 'success'
                              ? 'rgba(76, 175, 80, 0.05)'
                              : log.level === 'debug'
                              ? 'rgba(136, 132, 216, 0.05)'
                              : 'transparent',
                          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                        }}
                      >
                        <Typography
                          variant="body2"
                          component="div"
                          sx={{
                            display: 'flex',
                            gap: 1,
                            wordBreak: 'break-word',
                          }}
                        >
                          <span style={{ color: '#666', minWidth: '70px', fontSize: '0.7rem' }}>
                            {new Date(log.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </span>
                          <span style={{ 
                            fontWeight: 'bold', 
                            minWidth: '60px',
                            color: getLogLevelColor(log.level),
                            textTransform: 'uppercase',
                            fontSize: '0.7rem'
                          }}>
                            [{log.level}]
                          </span>
                          <span style={{ flex: 1 }}>{log.message}</span>
                        </Typography>
                      </Box>
                    ))
                  )}
                  <div ref={logsEndRef} />
                </Box>
              </Paper>
            </Paper>
          </Grid>
        </Grid>
      ) : (
        <FindingsTab config={config} />
      )}

      {/* Client Creation Dialog */}
      <Dialog
        open={clientDialogOpen}
        onClose={handleCloseClientDialog}
        fullWidth
        maxWidth="sm"
        aria-labelledby="client-creation-dialog-title"
      >
        <DialogTitle id="client-creation-dialog-title" sx={{ pb: 1 }}>
          {clientCreationStep === 4 ? "Client Created" : "Interactive Client Creation"}
        </DialogTitle>
        
        <DialogContent>
          {clientCreationStep < 4 && (
            <DialogContentText sx={{ mb: 2 }}>
              This wizard will guide you through creating a client and report in Plextrac.
            </DialogContentText>
          )}
          
          <Stepper activeStep={clientCreationStep} orientation="vertical">
            {clientCreationSteps.map((step, index) => (
              <Step key={index}>
                <StepLabel
                  optional={index === 3 ? <Typography variant="caption">Final Step</Typography> : null}
                  icon={step.icon}
                >
                  {step.label}
                </StepLabel>
                <StepContent>
                  {step.content}
                  <Box sx={{ mb: 2, mt: 1 }}>
                    <div>
                      <Button
                        variant="contained"
                        onClick={handleClientCreationNext}
                        sx={{ mr: 1 }}
                        disabled={clientCreationLoading}
                        endIcon={clientCreationLoading ? <CircularProgress size={16} /> : null}
                      >
                        {index === 3 ? 'Create Client & Report' : 'Continue'}
                      </Button>
                      <Button
                        disabled={index === 0 || clientCreationLoading}
                        onClick={handleClientCreationBack}
                        sx={{ mr: 1 }}
                      >
                        Back
                      </Button>
                    </div>
                  </Box>
                </StepContent>
              </Step>
            ))}
          </Stepper>
        </DialogContent>
        
        <DialogActions>
          <Button onClick={handleCloseClientDialog} color="primary">
            {clientCreationStep === 4 ? 'Close' : 'Cancel'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for alerts */}
      <Snackbar 
        open={alert.open} 
        autoHideDuration={6000} 
        onClose={handleAlertClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleAlertClose}
          severity={alert.severity}
          variant="filled"
          sx={{ width: '100%' }}
        >
          {alert.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Nessus2Plextrac;