import React, { useState, useEffect } from 'react';
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Checkbox,
  FormControl,
  InputLabel,
  Select,
  Tab,
  Tabs,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  FilterList as FilterIcon,
  Delete as DeleteIcon,
  PlaylistAddCheck as BatchIcon,
  ContentCopy as CopyIcon,
  Done as DoneIcon,
  Close as CloseIcon,
  LocalOffer as TagIcon,
  Search as SearchIcon,
} from '@mui/icons-material';

// Import Wails functions that we'll need to add to main/App.go
import {
  GetFindings,
  UpdateFinding,
  BulkUpdateFindings
} from '../wailsjs/go/main/App';

// Custom field item component - properly separated to avoid hooks rules violation
const CustomFieldItem = ({ 
  fieldOption, 
  currentFinding, 
  pendingChanges, 
  handleChangeFindingProperty 
}) => {
  const fields = currentFinding.fields || [];
  const field = fields.find(f => f.key === fieldOption.key);
  const currentValue = field ? field.value : '';
  
  // Check if the current value is custom (not in the predefined options)
  const isCustomValue = !fieldOption.options.includes(currentValue) && currentValue !== '';
  
  // State hooks are now correctly at the top level of this component
  const [showCustomInput, setShowCustomInput] = useState(isCustomValue);
  const [customValue, setCustomValue] = useState(isCustomValue ? currentValue : '');

  return (
    <Grid item xs={12} md={6}>
      <FormControl fullWidth margin="normal">
        <InputLabel>{fieldOption.label}</InputLabel>
        {showCustomInput ? (
          // Show text input when "Custom..." is selected
          <TextField
            label={fieldOption.label}
            value={customValue}
            onChange={(e) => {
              setCustomValue(e.target.value);
              handleChangeFindingProperty(currentFinding.flaw_id, 'customFields', {
                key: fieldOption.key,
                label: fieldOption.label,
                value: e.target.value
              });
            }}
            fullWidth
            variant="outlined"
            size="small"
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton 
                    size="small" 
                    onClick={() => {
                      setShowCustomInput(false);
                      setCustomValue('');
                    }}
                  >
                    <CloseIcon fontSize="small" />
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
        ) : (
          // Show dropdown when custom input is not active
          <Select
            value={
              pendingChanges[currentFinding.flaw_id]?.customFields?.key === fieldOption.key
                ? pendingChanges[currentFinding.flaw_id].customFields.value
                : currentValue
            }
            label={fieldOption.label}
            onChange={(e) => {
              if (e.target.value === 'Custom...') {
                setShowCustomInput(true);
              } else {
                handleChangeFindingProperty(currentFinding.flaw_id, 'customFields', {
                  key: fieldOption.key,
                  label: fieldOption.label,
                  value: e.target.value
                });
              }
            }}
          >
            <MenuItem value="">
              <em>None</em>
            </MenuItem>
            {fieldOption.options.map(option => (
              <MenuItem key={option} value={option}>{option}</MenuItem>
            ))}
          </Select>
        )}
      </FormControl>
    </Grid>
  );
};

const FindingsTab = ({ config }) => {
  // State for findings data
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedFindings, setSelectedFindings] = useState([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [alert, setAlert] = useState({ open: false, message: '', severity: 'info' });
  const [pendingChanges, setPendingChanges] = useState({});
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [currentFinding, setCurrentFinding] = useState(null);
  const [showCustomFields, setShowCustomFields] = useState(true);
  const [logs, setLogs] = useState([]);
  
  // State for filtering
  const [filters, setFilters] = useState({
    title: '',
    severity: '',
    status: ''
  });
  
  // Options for editing
  const severityOptions = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const statusOptions = ['Open', 'Closed', 'In Progress'];
  const customFieldOptions = [
    { 
      key: 'recommendation_title', 
      label: 'Recommendation Title', 
      options: ['Custom...'] 
    },
    { 
      key: 'owner', 
      label: 'Owner', 
      options: ['Systems Administrator', 'Network Engineer', 'Web Development Team', 'Custom...'] 
    }
  ];
  
  // Tags for quick selection
  const commonTags = [
    'priority_high', 'priority_medium', 'priority_low',
    'complexity_easy', 'complexity_intermediate', 'complexity_complex',
    'internal_finding', 'external_finding', 'webapp_finding'
  ];
  
  // Load findings on component mount or when config changes
  useEffect(() => {
    if (config.clientId && config.reportId) {
      loadFindings();
    }
  }, [config.clientId, config.reportId]);
  
  // Load findings from backend
  const loadFindings = async () => {
    if (!config.clientId || !config.reportId) {
      setAlert({
        open: true,
        message: 'Client ID and Report ID are required to load findings',
        severity: 'warning'
      });
      return;
    }
    
    setLoading(true);
    setLogs([]); // Clear any previous logs
    
    try {
      console.log("Fetching findings with config:", {
        username: config.username,
        password: "******", // Don't log actual password
        targetPlextrac: config.targetPlextrac,
        clientId: config.clientId,
        reportId: config.reportId
      });
      
      const result = await GetFindings({
        username: config.username,
        password: config.password,
        targetPlextrac: config.targetPlextrac,
        clientId: config.clientId,
        reportId: config.reportId
      });
      
      console.log("API response:", result);
      
      if (result && result.success) {
        // Ensure we have a findings array (even if empty)
        const findingsArray = result.findings || [];
        setFindings(findingsArray);
        
        setAlert({
          open: true,
          message: `Successfully loaded ${findingsArray.length} findings`,
          severity: 'success'
        });
        
        // Add a log entry
        setLogs(prevLogs => [...prevLogs, {
          time: new Date().toISOString(),
          level: 'success',
          message: `Loaded ${findingsArray.length} findings from Plextrac`
        }]);
      } else {
        console.error("Error from API:", result?.error);
        
        setAlert({
          open: true,
          message: result?.error || 'Failed to load findings from Plextrac',
          severity: 'error'
        });
        
        // Add an error log
        setLogs(prevLogs => [...prevLogs, {
          time: new Date().toISOString(),
          level: 'error',
          message: `Error: ${result?.error || 'Unknown error loading findings'}`
        }]);
      }
    } catch (error) {
      console.error("Exception when loading findings:", error);
      
      setAlert({
        open: true,
        message: `Error loading findings: ${error.message || 'Unknown error'}`,
        severity: 'error'
      });
      
      // Add an error log
      setLogs(prevLogs => [...prevLogs, {
        time: new Date().toISOString(),
        level: 'error',
        message: `Exception: ${error.message || 'Unknown error'}`
      }]);
    } finally {
      setLoading(false);
    }
  };
  
  // Handle row selection
  const handleSelectFinding = (findingId) => {
    setSelectedFindings(prev => {
      if (prev.includes(findingId)) {
        return prev.filter(id => id !== findingId);
      } else {
        return [...prev, findingId];
      }
    });
  };
  
  // Handle select all
  const handleSelectAll = () => {
    if (selectedFindings.length === filteredFindings.length) {
      setSelectedFindings([]);
    } else {
      setSelectedFindings(filteredFindings.map(finding => finding.flaw_id));
    }
  };
  
  // Handle changing a property for a single finding
  const handleChangeFindingProperty = (findingId, property, value) => {
    setPendingChanges(prev => ({
      ...prev,
      [findingId]: {
        ...(prev[findingId] || {}),
        [property]: value
      }
    }));
  };
  
  // Apply bulk changes to selected findings
  const applyBulkChanges = (property, value) => {
    // Update pending changes for all selected findings
    const newPendingChanges = { ...pendingChanges };
    
    if (property === 'tags') {
      // For tags, we need to handle them differently
      selectedFindings.forEach(findingId => {
        // Get the current tags for this finding
        const finding = findings.find(f => f.flaw_id === findingId);
        const currentTags = finding?.tags || [];
        
        // Add the new tag if it doesn't already exist
        if (!currentTags.includes(value)) {
          const updatedTags = [...currentTags, value];
          
          newPendingChanges[findingId] = {
            ...(newPendingChanges[findingId] || {}),
            [property]: updatedTags
          };
        }
      });
    } else {
      // For other properties (severity, status, etc.), handle normally
      selectedFindings.forEach(findingId => {
        newPendingChanges[findingId] = {
          ...(newPendingChanges[findingId] || {}),
          [property]: value
        };
      });
    }
    
    setPendingChanges(newPendingChanges);
    
    setAlert({
      open: true,
      message: `Applied ${property} change to ${selectedFindings.length} findings. Click "Apply Changes" to save.`,
      severity: 'info'
    });
  };


  // Open edit dialog for a finding
  const handleOpenEditDialog = (finding) => {
    setCurrentFinding(finding);
    setEditDialogOpen(true);
  };
  
  // Close edit dialog
  const handleCloseEditDialog = () => {
    setEditDialogOpen(false);
    setCurrentFinding(null);
  };
  
  // Save changes from edit dialog
  const handleSaveFromDialog = () => {
    if (!currentFinding) return;
    
    setEditDialogOpen(false);
    setCurrentFinding(null);
  };
  
  // Submit all pending changes
  const submitChanges = async () => {
    setLoading(true);
    try {
      // Group changes by type for efficiency
      const tagChanges = [];
      const severityChanges = [];
      const statusChanges = [];
      const customFieldChanges = [];
      
      // Process each finding with pending changes
      for (const [findingId, changes] of Object.entries(pendingChanges)) {
        // Handle different types of changes
        if (changes.tags) {
          tagChanges.push({ findingId, tags: changes.tags });
        }
        
        if (changes.severity) {
          severityChanges.push({ findingId, severity: changes.severity });
        }
        
        if (changes.status) {
          statusChanges.push({ findingId, status: changes.status });
        }
        
        if (changes.customFields) {
          customFieldChanges.push({ findingId, customFields: changes.customFields });
        }
      }
      
      // Submit bulk tag changes if any
      if (tagChanges.length > 0) {
        // Get all finding IDs that need tag updates
        const findingIds = tagChanges.map(t => t.findingId);
        
        // Collect all unique tags across all selected findings
        const allTags = new Set();
        tagChanges.forEach(change => {
          change.tags.forEach(tag => allTags.add(tag));
        });
        
        const tags = Array.from(allTags);
        
        console.log("Sending bulk tag update with tags:", tags);
        console.log("For findings:", findingIds);
        
        const result = await BulkUpdateFindings({
          username: config.username,
          password: config.password,
          targetPlextrac: config.targetPlextrac,
          clientId: config.clientId,
          reportId: config.reportId,
          findingIds: findingIds,
          updateType: 'tags',
          tags: tags
        });
        
        if (!result.success) {
          throw new Error(result.error || 'Failed to update tags');
        }
      }
      
      // Submit individual severity changes
      for (const { findingId, severity } of severityChanges) {
        const result = await UpdateFinding({
          username: config.username,
          password: config.password,
          targetPlextrac: config.targetPlextrac,
          clientId: config.clientId,
          reportId: config.reportId,
          findingId: findingId,
          updateType: 'severity',
          severity: severity
        });
        
        if (!result.success) {
          throw new Error(result.error || 'Failed to update severity');
        }
      }
      
      // Submit individual status changes
      for (const { findingId, status } of statusChanges) {
        const result = await UpdateFinding({
          username: config.username,
          password: config.password,
          targetPlextrac: config.targetPlextrac,
          clientId: config.clientId,
          reportId: config.reportId,
          findingId: findingId,
          updateType: 'status',
          status: status
        });
        
        if (!result.success) {
          throw new Error(result.error || 'Failed to update status');
        }
      }
      
      // Submit custom field changes
      for (const { findingId, customFields } of customFieldChanges) {
        const result = await UpdateFinding({
          username: config.username,
          password: config.password,
          targetPlextrac: config.targetPlextrac,
          clientId: config.clientId,
          reportId: config.reportId,
          findingId: findingId,
          updateType: 'customFields',
          customFields: customFields
        });
        
        if (!result.success) {
          throw new Error(result.error || 'Failed to update custom fields');
        }
      }
      
      // Clear pending changes and reload findings
      setPendingChanges({});
      await loadFindings();
      
      setAlert({
        open: true,
        message: 'Changes applied successfully',
        severity: 'success'
      });
    } catch (error) {
      setAlert({
        open: true,
        message: `Error applying changes: ${error.message || 'Unknown error'}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };
  
  // Filter findings based on current filters
  const filteredFindings = findings.filter(finding => {
    if (filters.title && !finding.title.toLowerCase().includes(filters.title.toLowerCase())) {
      return false;
    }
    if (filters.severity && finding.severity !== filters.severity) {
      return false;
    }
    if (filters.status && finding.status !== filters.status) {
      return false;
    }
    return true;
  });
  
  // Pagination handlers
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };
  
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };
  
  // Get findings for current page
  const paginatedFindings = filteredFindings.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );
  
  // Get a chip color based on severity
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'error';
      case 'High': return 'error';
      case 'Medium': return 'warning';
      case 'Low': return 'success';
      case 'Informational': return 'info';
      default: return 'default';
    }
  };
  
  // Get a chip color based on status
  const getStatusColor = (status) => {
    switch (status) {
      case 'Open': return 'error';
      case 'In Progress': return 'warning';
      case 'Closed': return 'success';
      default: return 'default';
    }
  };
  
  return (
    <Box sx={{ p: 2 }}>
      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Search & Filter Findings</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Search by Title"
              value={filters.title}
              onChange={(e) => setFilters(prev => ({ ...prev, title: e.target.value }))}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              size="small"
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select
                value={filters.severity}
                label="Severity"
                onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
              >
                <MenuItem value="">All</MenuItem>
                {severityOptions.map(option => (
                  <MenuItem key={option} value={option}>{option}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                value={filters.status}
                label="Status"
                onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              >
                <MenuItem value="">All</MenuItem>
                {statusOptions.map(option => (
                  <MenuItem key={option} value={option}>{option}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2} sx={{ display: 'flex', alignItems: 'center' }}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={loadFindings}
              disabled={loading}
              size="small"
              fullWidth
            >
              Refresh
            </Button>
          </Grid>
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={showCustomFields}
                  onChange={(e) => setShowCustomFields(e.target.checked)}
                  size="small"
                />
              }
              label="Show Custom Fields"
            />
          </Grid>
        </Grid>
      </Paper>
      
      {/* Bulk Edit Controls */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>
          Bulk Edit ({selectedFindings.length} selected)
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Set Severity</InputLabel>
              <Select
                value=""
                label="Set Severity"
                onChange={(e) => applyBulkChanges('severity', e.target.value)}
                disabled={!selectedFindings.length || loading}
              >
                <MenuItem value="" disabled>Select Severity</MenuItem>
                {severityOptions.map(option => (
                  <MenuItem key={option} value={option}>{option}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Set Status</InputLabel>
              <Select
                value=""
                label="Set Status"
                onChange={(e) => applyBulkChanges('status', e.target.value)}
                disabled={!selectedFindings.length || loading}
              >
                <MenuItem value="" disabled>Select Status</MenuItem>
                {statusOptions.map(option => (
                  <MenuItem key={option} value={option}>{option}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Add Tag</InputLabel>
              <Select
                value=""
                label="Add Tag"
                onChange={(e) => {
                  if (e.target.value) {
                    // Apply the selected tag directly
                    applyBulkChanges('tags', e.target.value);
                  }
                }}
                disabled={!selectedFindings.length || loading}
              >
                <MenuItem value="" disabled>Add Tag</MenuItem>
                {commonTags.map(tag => (
                  <MenuItem key={tag} value={tag}>{tag}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3} sx={{ display: 'flex', alignItems: 'center' }}>
            <Button
              variant="contained"
              color="primary"
              startIcon={loading ? <CircularProgress size={24} color="inherit" /> : <SaveIcon />}
              onClick={submitChanges}
              disabled={loading || Object.keys(pendingChanges).length === 0}
              fullWidth
              size="medium"
            >
              Apply Changes
            </Button>
          </Grid>
        </Grid>
      </Paper>
      
      {/* Findings Table */}
      <Paper sx={{ width: '100%', overflow: 'hidden' }}>
        <TableContainer sx={{ maxHeight: 440 }}>
          <Table stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={selectedFindings.length > 0 && selectedFindings.length < filteredFindings.length}
                    checked={filteredFindings.length > 0 && selectedFindings.length === filteredFindings.length}
                    onChange={handleSelectAll}
                    disabled={loading}
                  />
                </TableCell>
                <TableCell>Title</TableCell>
                <TableCell align="center">Severity</TableCell>
                <TableCell align="center">Status</TableCell>
                <TableCell>Tags</TableCell>
                {showCustomFields && <TableCell>Custom Fields</TableCell>}
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && !paginatedFindings.length ? (
                <TableRow>
                  <TableCell colSpan={showCustomFields ? 7 : 6} align="center">
                    <CircularProgress size={40} sx={{ my: 2 }} />
                    <Typography variant="body2" color="text.secondary">
                      Loading findings...
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : !paginatedFindings.length ? (
                <TableRow>
                  <TableCell colSpan={showCustomFields ? 7 : 6} align="center">
                    <Typography variant="body2" color="text.secondary" sx={{ my: 2 }}>
                      No findings match the current filters
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedFindings.map((finding) => {
                  const isSelected = selectedFindings.includes(finding.flaw_id);
                  const hasPendingChanges = !!pendingChanges[finding.flaw_id];
                  
                  return (
                    <TableRow
                      hover
                      key={finding.flaw_id}
                      selected={isSelected}
                      sx={{ 
                        '&.Mui-selected, &.Mui-selected:hover': { 
                          backgroundColor: hasPendingChanges ? '#e3f2fd' : undefined 
                        } 
                      }}
                    >
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={isSelected}
                          onChange={() => handleSelectFinding(finding.flaw_id)}
                          disabled={loading}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                          {finding.title}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={pendingChanges[finding.flaw_id]?.severity || finding.severity} 
                          color={getSeverityColor(pendingChanges[finding.flaw_id]?.severity || finding.severity)}
                          size="small"
                          variant={pendingChanges[finding.flaw_id]?.severity ? 'outlined' : 'filled'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={pendingChanges[finding.flaw_id]?.status || finding.status}
                          color={getStatusColor(pendingChanges[finding.flaw_id]?.status || finding.status)}
                          size="small"
                          variant={pendingChanges[finding.flaw_id]?.status ? 'outlined' : 'filled'}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {(pendingChanges[finding.flaw_id]?.tags || finding.tags || []).slice(0, 3).map((tag, index) => (
                            <Chip 
                              key={index} 
                              label={tag} 
                              size="small" 
                              variant={pendingChanges[finding.flaw_id]?.tags ? 'outlined' : 'filled'}
                            />
                          ))}
                          {(pendingChanges[finding.flaw_id]?.tags || finding.tags || []).length > 3 && (
                            <Chip 
                              label={`+${(pendingChanges[finding.flaw_id]?.tags || finding.tags || []).length - 3}`} 
                              size="small" 
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </TableCell>
                      {showCustomFields && (
                        <TableCell>
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            {(pendingChanges[finding.flaw_id]?.customFields || finding.fields || []).slice(0, 2).map((field, index) => (
                              <Box key={index} sx={{ display: 'flex', flexDirection: 'column' }}>
                                <Typography variant="caption" color="text.secondary">{field.label}:</Typography>
                                <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>{field.value}</Typography>
                              </Box>
                            ))}
                            {(pendingChanges[finding.flaw_id]?.customFields || finding.fields || []).length > 2 && (
                              <Typography variant="caption" color="text.secondary">
                                +{(pendingChanges[finding.flaw_id]?.customFields || finding.fields || []).length - 2} more fields
                              </Typography>
                            )}
                          </Box>
                        </TableCell>
                      )}
                      <TableCell align="center">
                        <Tooltip title="Edit Finding">
                          <IconButton 
                            size="small"
                            color="primary"
                            onClick={() => handleOpenEditDialog(finding)}
                            disabled={loading}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          rowsPerPageOptions={[5, 10, 25, 50]}
          component="div"
          count={filteredFindings.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>
      
      {/* Edit Finding Dialog */}
      <Dialog open={editDialogOpen} onClose={handleCloseEditDialog} fullWidth maxWidth="md">
        {currentFinding && (
          <>
            <DialogTitle>
              Edit Finding
              <IconButton
                aria-label="close"
                onClick={handleCloseEditDialog}
                sx={{ position: 'absolute', right: 8, top: 8 }}
              >
                <CloseIcon />
              </IconButton>
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="h6" gutterBottom>
                {currentFinding.title}
              </Typography>
              
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Severity</InputLabel>
                    <Select
                      value={pendingChanges[currentFinding.flaw_id]?.severity || currentFinding.severity}
                      label="Severity"
                      onChange={(e) => handleChangeFindingProperty(currentFinding.flaw_id, 'severity', e.target.value)}
                    >
                      {severityOptions.map(option => (
                        <MenuItem key={option} value={option}>{option}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Status</InputLabel>
                    <Select
                      value={pendingChanges[currentFinding.flaw_id]?.status || currentFinding.status}
                      label="Status"
                      onChange={(e) => handleChangeFindingProperty(currentFinding.flaw_id, 'status', e.target.value)}
                    >
                      {statusOptions.map(option => (
                        <MenuItem key={option} value={option}>{option}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Tags
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {commonTags.map(tag => {
                      const currentTags = pendingChanges[currentFinding.flaw_id]?.tags || currentFinding.tags || [];
                      const isSelected = currentTags.includes(tag);
                      
                      return (
                        <Chip
                          key={tag}
                          label={tag}
                          color={isSelected ? 'primary' : 'default'}
                          variant={isSelected ? 'filled' : 'outlined'}
                          onClick={() => {
                            // Toggle tag
                            const newTags = isSelected
                              ? currentTags.filter(t => t !== tag)
                              : [...currentTags, tag];
                            
                            handleChangeFindingProperty(currentFinding.flaw_id, 'tags', newTags);
                          }}
                          icon={isSelected ? <DoneIcon /> : <TagIcon />}
                        />
                      );
                    })}
                  </Box>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Custom Fields
                  </Typography>
                  <Grid container spacing={2}>
                    {customFieldOptions.map(fieldOption => (
                      <CustomFieldItem
                        key={fieldOption.key}
                        fieldOption={fieldOption}
                        currentFinding={currentFinding}
                        pendingChanges={pendingChanges}
                        handleChangeFindingProperty={handleChangeFindingProperty}
                      />
                    ))}
                  </Grid>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={handleCloseEditDialog}>Cancel</Button>
              <Button
                variant="contained"
                color="primary"
                onClick={submitChanges}
                disabled={Object.keys(pendingChanges).length === 0}
                startIcon={<SaveIcon />}
              >
                Save Changes
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
      
      {/* Alert */}
      <Snackbar
        open={alert.open}
        autoHideDuration={6000}
        onClose={() => setAlert(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setAlert(prev => ({ ...prev, open: false }))}
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

export default FindingsTab;