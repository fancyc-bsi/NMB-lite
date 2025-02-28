import React, { useState, useEffect } from 'react';
import { useTheme } from '@mui/material/styles';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  FormControl,
  Grid,
  IconButton,
  InputAdornment,
  InputLabel,
  List,
  ListItem,
  ListItemSecondaryAction,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Tab,
  Tabs,
  TextField,
  Typography,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  FilterList as FilterListIcon,
  Refresh as RefreshIcon,
  Save as SaveIcon,
  Clear as ClearIcon,
  Create as CreateIcon,
  Edit as EditIcon,
  Search as SearchIcon,
  Upload as UploadIcon,
  BugReport as BugReportIcon
} from '@mui/icons-material';

import { SelectCSVFile, UpdateCSVPath, GetCSVPath, GetConfigPath, SelectConfigFile,
  GetCategories, GetCategoryDetails, GetCategoryInfo, GetPluginsByCategory,
  FilterPluginsByName, GetNonMergedPlugins, AddPlugin, RemovePlugin,
  WriteChanges, ClearChanges, HasPendingChanges, ViewChanges,
  CreateCategory, UpdateCategory, DeleteCategory,
  SimulateFindings, WriteSimulationResultsToFile, ReadSimulationResultsFile } from '../wailsjs/go/main/App';

const PluginManager = () => {
  // Access theme
  const theme = useTheme();
  
  // State variables
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [csvPath, setCsvPath] = useState('');
  const [configPath, setConfigPath] = useState('');
  const [categories, setCategories] = useState([]);
  const [categoryDetails, setCategoryDetails] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [filterText, setFilterText] = useState('');
  const [pluginsInCategory, setPluginsInCategory] = useState([]);
  const [nonMergedPlugins, setNonMergedPlugins] = useState([]);
  const [selectedPlugins, setSelectedPlugins] = useState([]);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [changesText, setChangesText] = useState('');
  const [notification, setNotification] = useState({ open: false, message: '', severity: 'info' });
  const [simulationDialogOpen, setSimulationDialogOpen] = useState(false);
  const [simulationResults, setSimulationResults] = useState({ merged: {}, individual: [] });
  const [createCategoryDialog, setCreateCategoryDialog] = useState(false);
  const [newCategory, setNewCategory] = useState({ name: '', writeupDBID: '', writeupName: '' });
  const [editCategoryDialog, setEditCategoryDialog] = useState(false);
  const [editCategory, setEditCategory] = useState({ name: '', writeupDBID: '', writeupName: '' });
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [debugOutput, setDebugOutput] = useState('');
  const [isSaving, setIsSaving] = useState(false);

  // Helper function to normalize property access (handles both camelCase and PascalCase)
  const getPluginId = (plugin) => plugin.id || plugin.ID || '';
  const getPluginName = (plugin) => plugin.name || plugin.Name || 'Unknown';

  // Function to update nonMergedPlugins from simulation results
  const updateNonMergedPluginsFromSimulation = (individualFindings) => {
    // Make sure we have a valid array of findings
    if (!Array.isArray(individualFindings) || individualFindings.length === 0) {
      console.log("No individual findings to update");
      return;
    }
    
    console.log(`Updating nonMergedPlugins with ${individualFindings.length} individual findings`);
    
    // Normalize the findings to ensure consistent property names
    const normalizedFindings = individualFindings.map(finding => {
      return {
        id: finding.id || finding.ID || '',
        name: finding.name || finding.Name || 'Unknown',
      };
    });
    
    // Update nonMergedPlugins state, ensuring no duplicates
    setNonMergedPlugins(prevPlugins => {
      // Create a map of existing plugins by ID for quick lookup
      const existingPluginsMap = {};
      prevPlugins.forEach(plugin => {
        const id = getPluginId(plugin);
        if (id) {
          existingPluginsMap[id] = true;
        }
      });
      
      // Filter out findings that already exist in nonMergedPlugins
      const newFindings = normalizedFindings.filter(finding => !existingPluginsMap[finding.id]);
      
      // Add new findings to the existing plugins
      return [...prevPlugins, ...newFindings];
    });
    
    // Show notification about the update
    setNotification({
      open: true,
      message: `Added ${individualFindings.length} individual findings to the Add Plugins tab`,
      severity: 'success'
    });
  };

  // Debug helper functions
  const debugSimulationResponse = (result) => {
    const debugInfo = [];
    debugInfo.push("------ DEBUG SIMULATION RESPONSE ------");
    debugInfo.push(`Result type: ${typeof result}`);
    debugInfo.push(`Is array: ${Array.isArray(result)}`);
    
    if (Array.isArray(result)) {
      debugInfo.push(`Array length: ${result.length}`);
      
      // Log information about each element in the array
      result.forEach((item, index) => {
        debugInfo.push(`Element ${index}:`);
        debugInfo.push(`  Type: ${typeof item}`);
        debugInfo.push(`  Is null: ${item === null}`);
        debugInfo.push(`  Is array: ${Array.isArray(item)}`);
        debugInfo.push(`  Is object: ${typeof item === 'object' && item !== null && !Array.isArray(item)}`);
        
        if (typeof item === 'object' && item !== null) {
          debugInfo.push(`  Keys: ${Object.keys(item).join(', ')}`);
          
          // For merged findings (first element), show categories
          if (index === 0 && !Array.isArray(item)) {
            debugInfo.push("  Categories:");
            Object.keys(item).forEach(cat => {
              const plugins = item[cat];
              debugInfo.push(`    ${cat}: ${Array.isArray(plugins) ? plugins.length : 0} plugins`);
            });
          }
          
          // For individual findings (second element), show count
          if (index === 1 && Array.isArray(item)) {
            debugInfo.push(`  Individual findings count: ${item.length}`);
            
            if (item.length > 0) {
              debugInfo.push(`  First item ID: ${item[0].id || item[0].ID}`);
              debugInfo.push(`  First item Name: ${item[0].name || item[0].Name}`);
            }
          }
        }
      });
    } else if (typeof result === 'object' && result !== null) {
      debugInfo.push(`Object keys: ${Object.keys(result).join(', ')}`);
    }
    
    debugInfo.push("------ END DEBUG ------");
    
    // Update debug output state
    setDebugOutput(debugInfo.join('\n'));
    
    console.log(debugInfo.join('\n'));
    return result;
  };

  // Enhanced debug function to inspect complex objects
  const debugSimulateFindings = () => {
    setLoading(true);
    const debugInfo = [];
    debugInfo.push("Debug: Running direct SimulateFindings API call");
    setDebugOutput(debugInfo.join('\n'));
    
    // Call the API directly and log all the steps
    SimulateFindings()
      .then(result => {
        debugInfo.push("Debug: API call successful");
        debugInfo.push(`Debug: Raw result type: ${typeof result}`);
        debugInfo.push(`Debug: Is array? ${Array.isArray(result)}`);
        debugInfo.push(`Debug: Is null? ${result === null}`);
        
        // Check if we can access properties directly
        if (result !== null && typeof result === 'object') {
          debugInfo.push("Debug: Object inspection:");
          
          // Try to get object keys
          try {
            const keys = Object.keys(result);
            debugInfo.push(`Debug: Object keys: ${keys.join(', ')}`);
            
            // Loop through each key
            keys.forEach(key => {
              const value = result[key];
              debugInfo.push(`Debug: Key "${key}" has type: ${typeof value}, isArray: ${Array.isArray(value)}`);
              
              // If it's an object, try to get its keys
              if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
                try {
                  const subKeys = Object.keys(value);
                  debugInfo.push(`Debug: - Subkeys: ${subKeys.join(', ')}`);
                  debugInfo.push(`Debug: - First few subkeys: ${subKeys.slice(0, 5).map(k => `${k}=${typeof value[k]}`).join(', ')}`);
                } catch (e) {
                  debugInfo.push(`Debug: - Cannot get subkeys: ${e.message}`);
                }
              }
              
              // If it's an array, show some info about it
              if (Array.isArray(value)) {
                debugInfo.push(`Debug: - Array length: ${value.length}`);
                if (value.length > 0) {
                  debugInfo.push(`Debug: - First item type: ${typeof value[0]}`);
                  if (typeof value[0] === 'object' && value[0] !== null) {
                    try {
                      const itemKeys = Object.keys(value[0]);
                      debugInfo.push(`Debug: - First item keys: ${itemKeys.join(', ')}`);
                    } catch (e) {
                      debugInfo.push(`Debug: - Cannot get first item keys: ${e.message}`);
                    }
                  }
                }
              }
            });
          } catch (e) {
            debugInfo.push(`Debug: Cannot get object keys: ${e.message}`);
          }
          
          // Try to access common property patterns
          debugInfo.push("Debug: Direct property access:");
          
          // Try accessing properties directly
          const propertiesToTry = ['0', '1', 'merged', 'individual', 'Merged', 'Individual'];
          propertiesToTry.forEach(prop => {
            try {
              const value = result[prop];
              debugInfo.push(`Debug: - result["${prop}"] type: ${typeof value}, exists: ${value !== undefined}`);
            } catch (e) {
              debugInfo.push(`Debug: - Cannot access property "${prop}": ${e.message}`);
            }
          });
        }
        
        // Try to use Object.entries
        try {
          debugInfo.push("Debug: Using Object.entries to inspect structure:");
          const entries = Object.entries(result);
          debugInfo.push(`Debug: Found ${entries.length} entries`);
          
          entries.forEach(([key, value], index) => {
            if (index < 10) { // Limit to first 10 entries for readability
              debugInfo.push(`Debug: Entry ${index}: key="${key}", valueType=${typeof value}, isArray=${Array.isArray(value)}`);
            }
          });
        } catch (e) {
          debugInfo.push(`Debug: Object.entries failed: ${e.message}`);
        }
        
        setDebugOutput(debugInfo.join('\n'));
      })
      .catch(error => {
        debugInfo.push(`Debug: API call failed: ${error.message || error}`);
        setDebugOutput(debugInfo.join('\n'));
        
        console.error("Debug: API call failed", error);
        setNotification({
          open: true,
          message: `API call error: ${error.message || error}`,
          severity: 'error'
        });
      })
      .finally(() => {
        setLoading(false);
      });
  };

  // Debug config helper function
  const handleDebugChanges = async () => {
    try {
      setLoading(true);
      
      // Show current config info
      const debugInfo = [
        `Config Path: ${configPath}`,
        `Has Pending Changes: ${pendingChanges}`,
        `Categories: ${categories.length}`,
        `Selected Category: ${selectedCategory || "None"}`
      ];
      
      // Check if config file exists
      try {
        // This will indirectly check if the file exists
        const categoryDetails = await GetCategoryDetails();
        debugInfo.push(`✅ Config file accessible (found ${categoryDetails.length} categories)`);
      } catch (error) {
        debugInfo.push(`❌ Error accessing config file: ${error.message}`);
      }
      
      // Log the debug info
      console.log("Config Debug Info:", debugInfo.join("\n"));
      
      // Show debug info to user
      setDebugOutput(debugInfo.join("\n"));
      
      // Show the debug output panel
      const debugElem = document.getElementById('debug-output');
      if (debugElem) {
        debugElem.style.display = 'block';
      }
      
      setNotification({
        open: true,
        message: "Config debug info generated",
        severity: "info"
      });
    } catch (error) {
      console.error("Error debugging config:", error);
      setNotification({
        open: true,
        message: `Config debug error: ${error.message || error}`,
        severity: "error"
      });
    } finally {
      setLoading(false);
    }
  };

  // Initial data loading
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      setLoading(true);
      
      // Get paths
      const csvPathValue = await GetCSVPath();
      setCsvPath(csvPathValue);
      
      const configPathValue = await GetConfigPath();
      setConfigPath(configPathValue);
      
      // Load categories
      await loadCategories();
      
      // Check for pending changes
      const hasPendingChanges = await HasPendingChanges();
      setPendingChanges(hasPendingChanges);
      
      if (hasPendingChanges) {
        const changes = await ViewChanges();
        setChangesText(changes);
      }
      
      setLoading(false);
    } catch (error) {
      console.error('Error loading initial data:', error);
      setNotification({
        open: true,
        message: `Error loading data: ${error.message || error}`,
        severity: 'error'
      });
      setLoading(false);
    }
  };

  const loadCategories = async () => {
    try {
      const categoriesData = await GetCategories();
      setCategories(categoriesData);
      
      const categoryDetailsData = await GetCategoryDetails();
      setCategoryDetails(categoryDetailsData);
      
      // If we have a CSV file, load non-merged plugins
      if (csvPath) {
        const nonMergedData = await GetNonMergedPlugins();
        
        // Deduplicate plugins by ID
        const uniquePlugins = {};
        nonMergedData.forEach(plugin => {
          const id = plugin.ID || plugin.id;
          if (id) {
            uniquePlugins[id] = plugin;
          }
        });
        
        // Convert back to array
        const uniquePluginsArray = Object.values(uniquePlugins);
        setNonMergedPlugins(uniquePluginsArray);
      }
    } catch (error) {
      console.error('Error loading categories:', error);
      setNotification({
        open: true,
        message: `Error loading categories: ${error.message || error}`,
        severity: 'error'
      });
    }
  };

  const handleSelectCSV = async () => {
    try {
      const path = await SelectCSVFile();
      if (path) {
        await UpdateCSVPath(path);
        setCsvPath(path);
        
        // Reload data after CSV update
        await loadCategories();
        
        setNotification({
          open: true,
          message: 'CSV file updated successfully',
          severity: 'success'
        });
      }
    } catch (error) {
      console.error('Error selecting CSV file:', error);
      setNotification({
        open: true,
        message: `Error selecting CSV file: ${error.message || error}`,
        severity: 'error'
      });
    }
  };

  const handleSelectConfig = async () => {
    try {
      const path = await SelectConfigFile();
      if (path) {
        setConfigPath(path);
        
        // Reload data after config update
        await loadInitialData();
        
        setNotification({
          open: true,
          message: 'Configuration file updated successfully',
          severity: 'success'
        });
      }
    } catch (error) {
      console.error('Error selecting config file:', error);
      setNotification({
        open: true,
        message: `Error selecting config file: ${error.message || error}`,
        severity: 'error'
      });
    }
  };

  const handleTabChange = async (_, newValue) => {
    setActiveTab(newValue);
    
    // Refresh data when switching to a tab that needs fresh data
    if (newValue === 0) {
      // Manage Categories tab - reload categories
      await handleRefresh();
    } else if (newValue === 1) {
      // Add Plugins tab - reload non-merged plugins
      try {
        setLoading(true);
        await loadCategories();
        const nonMergedData = await GetNonMergedPlugins();
        setNonMergedPlugins(nonMergedData);
        setLoading(false);
      } catch (error) {
        console.error('Error loading non-merged plugins:', error);
        setLoading(false);
      }
    } else if (newValue === 2 && selectedCategory) {
      // Remove Plugins tab - reload plugins for selected category
      try {
        setLoading(true);
        const plugins = await GetPluginsByCategory(selectedCategory);
        setPluginsInCategory(plugins);
        setLoading(false);
      } catch (error) {
        console.error('Error loading plugins:', error);
        setLoading(false);
      }
    } else if (newValue === 3) {
      // Changes tab - reload pending changes
      try {
        setLoading(true);
        const hasPendingChanges = await HasPendingChanges();
        setPendingChanges(hasPendingChanges);
        
        if (hasPendingChanges) {
          const changes = await ViewChanges();
          setChangesText(changes);
        }
        setLoading(false);
      } catch (error) {
        console.error('Error checking pending changes:', error);
        setLoading(false);
      }
    }
  };

  const handleRefresh = async () => {
    try {
      setLoading(true);
      console.log("Refreshing data...");
      await loadCategories();
      
      // If we're on a category-specific tab, reload the plugins for the selected category
      if (activeTab === 1 || activeTab === 2) {
        if (selectedCategory) {
          const plugins = await GetPluginsByCategory(selectedCategory);
          setPluginsInCategory(plugins);
        }
      }
      
      // Check for pending changes
      const hasPendingChanges = await HasPendingChanges();
      setPendingChanges(hasPendingChanges);
      
      if (hasPendingChanges) {
        const changes = await ViewChanges();
        setChangesText(changes);
      }
      
      setNotification({
        open: true,
        message: 'Data refreshed successfully',
        severity: 'success'
      });
    } catch (error) {
      console.error('Error refreshing data:', error);
      setNotification({
        open: true,
        message: `Error refreshing data: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };
  

  const handleCategoryChange = async (event) => {
    const category = event.target.value;
    setSelectedCategory(category);
    setFilterText('');
    setPage(0);
    
    try {
      setLoading(true);
      
      // Get plugins for the selected category
      if (category) {
        const plugins = await GetPluginsByCategory(category);
        setPluginsInCategory(plugins);
      } else {
        setPluginsInCategory([]);
      }
      
      // If we're on the Add Plugins tab, also refresh the non-merged plugins
      if (activeTab === 1) {
        const nonMergedData = await GetNonMergedPlugins();
        setNonMergedPlugins(nonMergedData);
      }
      
      setLoading(false);
    } catch (error) {
      console.error('Error loading plugins:', error);
      setNotification({
        open: true,
        message: `Error loading plugins: ${error.message || error}`,
        severity: 'error'
      });
      setLoading(false);
    }
  };

  const handleFilterChange = async (event) => {
    const filter = event.target.value;
    setFilterText(filter);
    setPage(0);
    
    if (selectedCategory) {
      try {
        const plugins = await FilterPluginsByName(selectedCategory, filter);
        setPluginsInCategory(plugins);
      } catch (error) {
        console.error('Error filtering plugins:', error);
        setNotification({
          open: true,
          message: `Error filtering plugins: ${error.message || error}`,
          severity: 'error'
        });
      }
    }
  };

  const handleAddPlugin = async (pluginId) => {
    if (!selectedCategory) {
      setNotification({
        open: true,
        message: 'Please select a category first',
        severity: 'warning'
      });
      return;
    }
    
    try {
      setLoading(true);
      console.log(`Adding plugin ${pluginId} to category ${selectedCategory}`);
      await AddPlugin(selectedCategory, pluginId);
      
      // Update pending changes
      const hasPendingChanges = await HasPendingChanges();
      setPendingChanges(hasPendingChanges);
      
      if (hasPendingChanges) {
        const changes = await ViewChanges();
        setChangesText(changes);
      }
      
      // Remove from the non-merged list if it's there
      setNonMergedPlugins(prevPlugins => 
        prevPlugins.filter(plugin => {
          const id = plugin.id || plugin.ID;
          return id !== pluginId;
        })
      );
      
      // If we're on the "Remove Plugins" tab, refresh the category's plugins
      if (activeTab === 2) {
        const plugins = await GetPluginsByCategory(selectedCategory);
        setPluginsInCategory(plugins);
      }
      
      setNotification({
        open: true,
        message: `Plugin ${pluginId} added to ${selectedCategory}`,
        severity: 'success'
      });
    } catch (error) {
      console.error('Error adding plugin:', error);
      setNotification({
        open: true,
        message: `Error adding plugin: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRemovePlugin = async (pluginId) => {
    try {
      setLoading(true);
      console.log(`Removing plugin ${pluginId} from category ${selectedCategory}`);
      
      // Call the Go function to remove the plugin
      await RemovePlugin(selectedCategory, pluginId);
      
      // Show success notification
      setNotification({
        open: true,
        message: `Plugin ${pluginId} removed from ${selectedCategory}`,
        severity: 'success'
      });
      
      // Check if we need to update pending changes
      const hasPendingChanges = await HasPendingChanges();
      setPendingChanges(hasPendingChanges);
      
      if (hasPendingChanges) {
        const changes = await ViewChanges();
        setChangesText(changes);
      }
      
      // Refresh the plugins list
      const plugins = await GetPluginsByCategory(selectedCategory);
      setPluginsInCategory(plugins);
      
      // Also update non-merged plugins since the removed plugin might now be available to add
      const nonMergedData = await GetNonMergedPlugins();
      setNonMergedPlugins(nonMergedData);
      
    } catch (error) {
      console.error('Error removing plugin:', error);
      setNotification({
        open: true,
        message: `Error removing plugin: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleWriteChanges = async () => {
    // Prevent multiple simultaneous save attempts
    if (isSaving) {
      console.log("A save operation is already in progress");
      return;
    }
  
    try {
      if (!pendingChanges) {
        setNotification({
          open: true,
          message: 'No changes to save',
          severity: 'info'
        });
        return;
      }
  
      setIsSaving(true);
      setLoading(true);
      console.log("Writing changes to file:", configPath);
      
      // Add timeout handling for the WriteChanges call
      const writeWithTimeout = async (timeout = 15000) => {
        return new Promise(async (resolve, reject) => {
          // Create a timeout that will reject the promise if it takes too long
          const timeoutId = setTimeout(() => {
            console.error(`WriteChanges operation timed out after ${timeout}ms`);
            reject(new Error(`Save operation timed out after ${timeout}ms. The backend may still be processing.`));
          }, timeout);
          
          try {
            // Attempt to call WriteChanges
            console.log("Calling WriteChanges Go function...");
            const result = await WriteChanges();
            clearTimeout(timeoutId); // Clear timeout on success
            resolve(result);
          } catch (error) {
            clearTimeout(timeoutId); // Clear timeout on error
            reject(error);
          }
        });
      };
      
      // Call the WriteChanges with timeout
      await writeWithTimeout();
      
      console.log("WriteChanges completed successfully");
      
      // Update UI state
      setPendingChanges(false);
      setChangesText('');
      
      // Show success notification
      setNotification({
        open: true,
        message: 'Changes saved successfully to config file',
        severity: 'success'
      });
      
      // UPDATED: Refresh data immediately after successful save
      console.log("Refreshing data after save...");
      await handleRefresh();
      
    } catch (error) {
      console.error('Error writing changes:', error);
      
      setNotification({
        open: true,
        message: `Error writing changes: ${error.message || error}`,
        severity: 'error'
      });
      
      // Try to refresh even after error to get the latest state
      try {
        await handleRefresh();
      } catch (refreshError) {
        console.error("Failed to refresh data after error:", refreshError);
      }
    } finally {
      setLoading(false);
      setIsSaving(false);
    }
  };

  const handleClearChanges = async () => {
    try {
      setLoading(true);
      await ClearChanges();
      
      // Update pending changes state
      setPendingChanges(false);
      setChangesText('');
      
      setNotification({
        open: true,
        message: 'Changes cleared',
        severity: 'info'
      });
    } catch (error) {
      console.error('Error clearing changes:', error);
      setNotification({
        open: true,
        message: `Error clearing changes: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  // File-based simulation function that updates nonMergedPlugins
  const handleFileBasedSimulation = async () => {
    try {
      setLoading(true);
      console.log("Running file-based simulation...");
      
      // First verify that CSV path is set
      if (!csvPath) {
        setNotification({
          open: true,
          message: "Please select a CSV file first",
          severity: "warning"
        });
        return;
      }
      
      // Call the function to write simulation results to file
      const filePath = await WriteSimulationResultsToFile();
      console.log("Simulation results written to:", filePath);
      
      if (!filePath) {
        setNotification({
          open: true,
          message: "Failed to generate simulation results file",
          severity: "error"
        });
        return;
      }
      
      // Read the results file
      const jsonData = await ReadSimulationResultsFile(filePath);
      console.log("Read simulation results data of length:", jsonData?.length || 0);
      
      // Parse the JSON
      let resultObj;
      try {
        resultObj = JSON.parse(jsonData);
        console.log("Parsed simulation results successfully");
      } catch (error) {
        console.error("Error parsing simulation results JSON:", error);
        console.log("First 100 chars of JSON data:", jsonData?.substring(0, 100));
        setNotification({
          open: true,
          message: "Error parsing simulation results: " + error.message,
          severity: "error"
        });
        return;
      }
      
      console.log("Parsed simulation results:", resultObj);
      
      // Extract merged and individual findings
      const mergedFindings = resultObj.merged || {};
      const individualFindings = resultObj.individual || [];
      
      console.log(`Found ${Object.keys(mergedFindings).length} merged categories and ${individualFindings.length} individual findings`);
      
      // Set the simulation results
      setSimulationResults({
        merged: mergedFindings,
        individual: individualFindings
      });
      
      updateNonMergedPluginsFromSimulation(individualFindings);
      
      // Open the dialog to show the results
      setSimulationDialogOpen(true);
      
      // Show notification with summary info
      setNotification({
        open: true,
        message: `Simulation complete. Found ${Object.keys(mergedFindings).length} merged categories and ${individualFindings.length} individual findings.`,
        severity: 'success'
      });
      
    } catch (error) {
      console.error('Error in file-based simulation:', error);
      setNotification({
        open: true,
        message: `Error running simulation: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateFindings = async () => {
    try {
      setLoading(true);
      console.log("Running simulation...");
      
      // Call the simulate function
      const result = await SimulateFindings();
      
      console.log("Raw simulation result type:", typeof result);
      console.log("Is array:", Array.isArray(result));
      console.log("Is null:", result === null);
      
      // Initialize empty structures for merged and individual findings
      let mergedFindings = {};
      let individualFindings = [];
      
      // Check what we're dealing with
      if (result !== null && typeof result === 'object') {
        console.log("Result object keys:", Object.keys(result));
        
        // Try different possible property names
        if (result.merged) {
          mergedFindings = result.merged;
        } else if (result["0"]) {
          // Result might be returned as an object with numeric keys
          mergedFindings = result["0"];
        }
        
        if (result.individual) {
          individualFindings = result.individual;
        } else if (result["1"]) {
          individualFindings = result["1"];
        }
        
        // If we still don't have values, try to loop through all properties
        if (Object.keys(mergedFindings).length === 0 && individualFindings.length === 0) {
          for (const key in result) {
            const value = result[key];
            console.log(`Checking key: ${key}, type: ${typeof value}, isArray: ${Array.isArray(value)}`);
            
            // If it's an object with string keys, it's likely the merged findings
            if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
              mergedFindings = value;
              console.log("Found merged findings in key:", key);
            }
            
            // If it's an array, it's likely the individual findings
            if (Array.isArray(value)) {
              individualFindings = value;
              console.log("Found individual findings in key:", key);
            }
          }
        }
      }
      
      console.log("Processed merged findings:", mergedFindings);
      console.log("Categories:", Object.keys(mergedFindings));
      console.log("Processed individual findings count:", individualFindings.length);
      
      // Set the simulation results
      setSimulationResults({
        merged: mergedFindings || {},
        individual: individualFindings || []
      });
      
      // Show notification with summary info
      setNotification({
        open: true,
        message: `Simulation complete. Found ${Object.keys(mergedFindings).length} merged categories and ${individualFindings.length} individual findings.`,
        severity: 'success'
      });
      
      // Open the dialog to show the results
      setSimulationDialogOpen(true);
      
    } catch (error) {
      console.error('Error simulating findings:', error);
      setNotification({
        open: true,
        message: `Error simulating findings: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCategory = () => {
    setNewCategory({ name: '', writeupDBID: '', writeupName: '' });
    setCreateCategoryDialog(true);
  };

  const handleSaveNewCategory = async () => {
    try {
      setLoading(true);
      await CreateCategory(newCategory.name, newCategory.writeupDBID, newCategory.writeupName);
      
      // Reload categories
      await loadCategories();
      
      setCreateCategoryDialog(false);
      setNotification({
        open: true,
        message: `Category ${newCategory.name} created successfully`,
        severity: 'success'
      });
    } catch (error) {
      console.error('Error creating category:', error);
      setNotification({
        open: true,
        message: `Error creating category: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleEditCategory = async (categoryName) => {
    try {
      setLoading(true);
      const categoryInfo = await GetCategoryInfo(categoryName);
      setEditCategory({
        name: categoryInfo.name,
        writeupDBID: categoryInfo.writeup_db_id,
        writeupName: categoryInfo.writeup_name
      });
      setEditCategoryDialog(true);
    } catch (error) {
      console.error('Error getting category info:', error);
      setNotification({
        open: true,
        message: `Error getting category info: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEditCategory = async () => {
    try {
      setLoading(true);
      await UpdateCategory(editCategory.name, editCategory.writeupDBID, editCategory.writeupName);
      
      // Reload categories
      await loadCategories();
      
      setEditCategoryDialog(false);
      setNotification({
        open: true,
        message: `Category ${editCategory.name} updated successfully`,
        severity: 'success'
      });
    } catch (error) {
      console.error('Error updating category:', error);
      setNotification({
        open: true,
        message: `Error updating category: ${error.message || error}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCategory = async (categoryName) => {
    const confirm = window.confirm(`Are you sure you want to delete category ${categoryName}?`);
    if (confirm) {
      try {
        setLoading(true);
        await DeleteCategory(categoryName);
        
        // Refresh categories list
        await loadCategories();
        
        // Reset selected category if it's the one that was deleted
        if (selectedCategory === categoryName) {
          setSelectedCategory('');
          setPluginsInCategory([]);
        }
        
        // Also update non-merged plugins since plugins from the deleted category might now be available
        if (csvPath) {
          const nonMergedData = await GetNonMergedPlugins();
          setNonMergedPlugins(nonMergedData);
        }
        
        setNotification({
          open: true,
          message: `Category ${categoryName} deleted successfully`,
          severity: 'success'
        });
      } catch (error) {
        console.error('Error deleting category:', error);
        setNotification({
          open: true,
          message: `Error deleting category: ${error.message || error}`,
          severity: 'error'
        });
      } finally {
        setLoading(false);
      }
    }
  };

  const handleChangePage = (_, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleCloseNotification = () => {
    setNotification({ ...notification, open: false });
  };

  const toggleDebugOutput = () => {
    const debugElem = document.getElementById('debug-output');
    if (debugElem) {
      const isVisible = debugElem.style.display !== 'none';
      debugElem.style.display = isVisible ? 'none' : 'block';
    }
  };

  return (
    <Box sx={{ p: 3, color: 'text.primary' }}>
      <Typography variant="h4" gutterBottom>
        Plugin Manager
      </Typography>
      
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Config File</Typography>
              <Grid container spacing={2} alignItems="center">
                <Grid item xs>
                  <TextField
                    fullWidth
                    variant="outlined"
                    size="small"
                    value={configPath}
                    disabled
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleSelectConfig} edge="end">
                            <UploadIcon />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>CSV File</Typography>
              <Grid container spacing={2} alignItems="center">
                <Grid item xs>
                  <TextField
                    fullWidth
                    variant="outlined"
                    size="small"
                    value={csvPath}
                    disabled
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleSelectCSV} edge="end">
                            <UploadIcon />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      
      {!csvPath && (
        <Alert 
          severity="warning" 
          sx={{ mb: 3 }}
        >
          Please select a CSV file to load findings
        </Alert>
      )}
      
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant="fullWidth"
        >
          <Tab label="Manage Categories" />
          <Tab label="Add Plugins" disabled={!csvPath} />
          <Tab label="Remove Plugins" disabled={!csvPath} />
          <Tab label="Changes" />
          <Tab label="Simulation" disabled={!csvPath} />
        </Tabs>
        
        {/* Tab 1: Manage Categories */}
        {activeTab === 0 && (
          <Box p={3}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Categories</Typography>
            <Box>
              <Button
                variant="outlined"
                color="info"
                startIcon={<RefreshIcon />}
                onClick={handleRefresh}
                sx={{ mr: 2 }}
              >
                Refresh
              </Button>
              <Button
                variant="contained"
                color="primary"
                startIcon={<AddIcon />}
                onClick={handleCreateCategory}
              >
                Create Category
              </Button>
            </Box>
          </Box>
            
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>Name</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Writeup ID</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Writeup Name</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Plugin Count</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {categoryDetails.map((category) => (
                    <TableRow key={category.name} hover sx={{ '&:hover': { backgroundColor: theme.palette.action.hover } }}>
                      <TableCell>{category.name}</TableCell>
                      <TableCell>{category.writeup_db_id}</TableCell>
                      <TableCell>{category.writeup_name}</TableCell>
                      <TableCell>{category.plugin_count}</TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleEditCategory(category.name)}
                        >
                          <EditIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => handleDeleteCategory(category.name)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
        
        {/* Tab 2: Add Plugins */}
        {activeTab === 1 && (
          <Box p={3}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <FormControl variant="outlined" size="small" sx={{ width: 250 }}>
              <InputLabel>Select Category</InputLabel>
              <Select
                value={selectedCategory}
                onChange={handleCategoryChange}
                label="Select Category"
              >
                {categories.map((category) => (
                  <MenuItem key={category} value={category}>
                    {category}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            
            <Button
              variant="outlined"
              color="info"
              startIcon={<RefreshIcon />}
              onClick={handleRefresh}
            >
              Refresh
            </Button>
          </Box>
          
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">
              Available Plugins ({nonMergedPlugins.length})
            </Typography>      
              
              <Box display="flex" alignItems="center">
                {simulationResults.individual && simulationResults.individual.length > 0 && (
                  <Chip 
                    label={`${simulationResults.individual.length} from simulation`} 
                    color="primary" 
                    variant="outlined" 
                    size="small" 
                    sx={{ mr: 2 }}
                  />
                )}
                
                <TextField
                  variant="outlined"
                  size="small"
                  placeholder="Filter plugins..."
                  value={filterText}
                  onChange={handleFilterChange}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    ),
                  }}
                />
              </Box>
            </Box>
            
            {nonMergedPlugins.length === 0 ? (
              <Alert severity="info" sx={{ mb: 3 }}>
                No plugins available to add. Run a simulation to find available plugins.
              </Alert>
            ) : (
              <>
                <Paper variant="outlined" sx={{ mb: 2 }}>
                  <Box sx={{ px: 2, py: 1, bgcolor: 'background.paper', borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Typography variant="subtitle2">
                      Available Plugins to Add
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Select a category above, then add plugins to that category.
                    </Typography>
                  </Box>
                  
                  <TableContainer sx={{ maxHeight: 400 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 'bold' }}>ID</TableCell>
                          <TableCell sx={{ fontWeight: 'bold' }}>Name</TableCell>
                          <TableCell align="center" sx={{ fontWeight: 'bold' }}>Action</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {nonMergedPlugins
                          .filter(plugin => 
                            filterText === '' || 
                            (getPluginName(plugin).toLowerCase().includes(filterText.toLowerCase())) ||
                            (getPluginId(plugin).includes(filterText))
                          )
                          .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                          .map((plugin) => (
                            <TableRow 
                              key={getPluginId(plugin)} 
                              hover
                              sx={{ '&:hover': { backgroundColor: theme.palette.action.hover } }}
                            >
                              <TableCell>{getPluginId(plugin)}</TableCell>
                              <TableCell>{getPluginName(plugin)}</TableCell>
                              <TableCell align="center">
                                <Button
                                  variant="contained"
                                  color="primary"
                                  size="small"
                                  startIcon={<AddIcon />}
                                  onClick={() => handleAddPlugin(getPluginId(plugin))}
                                  disabled={!selectedCategory}
                                >
                                  Add
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                          
                        {nonMergedPlugins
                          .filter(plugin => 
                            filterText === '' || 
                            (getPluginName(plugin).toLowerCase().includes(filterText.toLowerCase())) ||
                            (getPluginId(plugin).includes(filterText))
                          ).length === 0 && (
                            <TableRow>
                              <TableCell colSpan={3} align="center">
                                <Typography variant="body2" sx={{ py: 2 }} color="text.secondary">
                                  No plugins found matching your filter criteria
                                </Typography>
                              </TableCell>
                            </TableRow>
                          )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  
                  <TablePagination
                    component="div"
                    count={nonMergedPlugins.filter(plugin => 
                      filterText === '' || 
                      (getPluginName(plugin).toLowerCase().includes(filterText.toLowerCase())) ||
                      (getPluginId(plugin).includes(filterText))
                    ).length}
                    page={page}
                    onPageChange={handleChangePage}
                    rowsPerPage={rowsPerPage}
                    onRowsPerPageChange={handleChangeRowsPerPage}
                    rowsPerPageOptions={[5, 10, 25, 50]}
                  />
                </Paper>
                
                {!selectedCategory && (
                  <Alert severity="warning">
                    Please select a category above to add plugins to it.
                  </Alert>
                )}
              </>
            )}
            
            {nonMergedPlugins.length === 0 && (
              <Box mt={3} display="flex" flexDirection="column" alignItems="center">
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  No plugins available to add. Run a simulation to find available plugins.
                </Typography>
                <Button
                  variant="outlined"
                  color="primary"
                  onClick={() => setActiveTab(4)} // Switch to Simulation tab
                  startIcon={<RefreshIcon />}
                  sx={{ mt: 1 }}
                >
                  Go to Simulation
                </Button>
              </Box>
            )}
          </Box>
        )}
        
        {/* Tab 3: Remove Plugins */}
        {activeTab === 2 && (
          <Box p={3}>
            <FormControl fullWidth variant="outlined" size="small" sx={{ mb: 3 }}>
              <InputLabel>Select Category</InputLabel>
              <Select
                value={selectedCategory}
                onChange={handleCategoryChange}
                label="Select Category"
              >
                {categories.map((category) => (
                  <MenuItem key={category} value={category}>
                    {category}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            
            <Typography variant="h6" gutterBottom>
              Plugins in {selectedCategory || "selected category"}
            </Typography>
            
            <TextField
              fullWidth
              variant="outlined"
              size="small"
              placeholder="Filter plugins..."
              value={filterText}
              onChange={handleFilterChange}
              sx={{ mb: 2 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
            
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>ID</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Name</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pluginsInCategory
                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                    .map((plugin) => (
                      <TableRow key={getPluginId(plugin)} hover sx={{ '&:hover': { backgroundColor: theme.palette.action.hover } }}>
                        <TableCell>{getPluginId(plugin)}</TableCell>
                        <TableCell>{getPluginName(plugin)}</TableCell>
                        <TableCell>
                          <Button
                            variant="contained"
                            color="error"
                            size="small"
                            startIcon={<DeleteIcon />}
                            onClick={() => handleRemovePlugin(getPluginId(plugin))}
                          >
                            Remove
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
            
            <TablePagination
              component="div"
              count={pluginsInCategory.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[5, 10, 25, 50]}
            />
          </Box>
        )}
        
        {/* Tab 4: Changes */}
        {activeTab === 3 && (
          <Box p={3}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">Pending Changes</Typography>
              <Box>
                <Button
                  variant="outlined"
                  color="info"
                  startIcon={<RefreshIcon />}
                  onClick={handleRefresh}
                  sx={{ mr: 1 }}
                >
                  Refresh
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<SaveIcon />}
                  onClick={handleWriteChanges}
                  disabled={!pendingChanges}
                  sx={{ mr: 1 }}
                >
                  Save Changes
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<ClearIcon />}
                  onClick={handleClearChanges}
                  disabled={!pendingChanges}
                  sx={{ mr: 1 }}
                >
                  Clear Changes
                </Button>
                <Button
                  variant="outlined"
                  color="secondary"
                  startIcon={<BugReportIcon />}
                  onClick={handleDebugChanges}
                >
                  Debug Config
                </Button>
              </Box>
            </Box>
            
            {pendingChanges ? (
              <Paper elevation={0} variant="outlined" sx={{ p: 2, bgcolor: 'background.paper' }}>
                <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
                  {changesText}
                </pre>
              </Paper>
            ) : (
              <Alert severity="info">
                No pending changes
              </Alert>
            )}
          </Box>
        )}
        
        {/* Tab 5: Simulation */}
        {activeTab === 4 && (
          <Box p={3}>
            <Typography variant="body1" paragraph>
              Simulate how your findings will be processed based on your current configuration.
              This will show which findings will be merged into categories and which ones will remain as individual findings.
            </Typography>
            
            <Box display="flex" alignItems="center" mb={2}>
              <Button
                variant="contained"
                color="primary"
                startIcon={<RefreshIcon />}
                onClick={handleFileBasedSimulation}
                disabled={!csvPath}
                sx={{ mr: 2 }}
              >
                Run Simulation
              </Button>
              
              {/* Debug buttons - for troubleshooting */}
              <Button
                variant="outlined"
                color="secondary"
                startIcon={<BugReportIcon />}
                onClick={debugSimulateFindings}
                disabled={!csvPath}
                sx={{ mr: 2 }}
              >
                Debug API Call
              </Button>
              
              <Button
                variant="outlined"
                color="info"
                onClick={toggleDebugOutput}
              >
                Toggle Debug Output
              </Button>
            </Box>
            
            {/* Debug output area */}
            <Paper 
              id="debug-output"
              elevation={0} 
              variant="outlined" 
              sx={{ 
                p: 2, 
                mb: 3, 
                bgcolor: 'background.paper', 
                display: 'none', 
                maxHeight: '300px', 
                overflow: 'auto'
              }}
            >
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Debug Output:
              </Typography>
              <pre style={{ whiteSpace: 'pre-wrap', margin: 0, fontSize: '0.8rem' }}>
                {debugOutput || 'No debug output available'}
              </pre>
            </Paper>
            
            {/* Show summary of last simulation if available */}
            {simulationResults && (
              Object.keys(simulationResults.merged || {}).length > 0 || 
              (simulationResults.individual && simulationResults.individual.length > 0)
            ) && (
              <Paper sx={{ mt: 3, p: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Last Simulation Summary:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="body2">
                      <strong>Categories with Merged Findings:</strong> {Object.keys(simulationResults.merged || {}).length}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="body2">
                      <strong>Individual Findings:</strong> {(simulationResults.individual || []).length}
                    </Typography>
                  </Grid>
                </Grid>
                <Button 
                  variant="outlined" 
                  size="small" 
                  sx={{ mt: 1 }}
                  onClick={() => setSimulationDialogOpen(true)}
                >
                  View Details
                </Button>
              </Paper>
            )}
          </Box>
        )}
      </Paper>
      
      {/* Create Category Dialog */}
      <Dialog open={createCategoryDialog} onClose={() => setCreateCategoryDialog(false)}>
        <DialogTitle>Create New Category</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Category Name"
            fullWidth
            variant="outlined"
            value={newCategory.name}
            onChange={(e) => setNewCategory({ ...newCategory, name: e.target.value })}
          />
          <TextField
            margin="dense"
            label="Writeup DB ID"
            fullWidth
            variant="outlined"
            value={newCategory.writeupDBID}
            onChange={(e) => setNewCategory({ ...newCategory, writeupDBID: e.target.value })}
          />
          <TextField
            margin="dense"
            label="Writeup Name"
            fullWidth
            variant="outlined"
            value={newCategory.writeupName}
            onChange={(e) => setNewCategory({ ...newCategory, writeupName: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateCategoryDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleSaveNewCategory}
            variant="contained" 
            color="primary"
            disabled={!newCategory.name}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Edit Category Dialog */}
      <Dialog open={editCategoryDialog} onClose={() => setEditCategoryDialog(false)}>
        <DialogTitle>Edit Category</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Category Name"
            fullWidth
            variant="outlined"
            value={editCategory.name}
            disabled
          />
          <TextField
            margin="dense"
            label="Writeup DB ID"
            fullWidth
            variant="outlined"
            value={editCategory.writeupDBID}
            onChange={(e) => setEditCategory({ ...editCategory, writeupDBID: e.target.value })}
          />
          <TextField
            margin="dense"
            label="Writeup Name"
            fullWidth
            variant="outlined"
            value={editCategory.writeupName}
            onChange={(e) => setEditCategory({ ...editCategory, writeupName: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditCategoryDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleSaveEditCategory}
            variant="contained" 
            color="primary"
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Simulation Results Dialog */}
      <Dialog
        open={simulationDialogOpen}
        onClose={() => setSimulationDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Simulation Results
          <IconButton
            aria-label="close"
            onClick={() => setSimulationDialogOpen(false)}
            sx={{
              position: 'absolute',
              right: 8,
              top: 8,
              color: (theme) => theme.palette.grey[500],
            }}
          >
            <ClearIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Typography variant="h6" gutterBottom>
            Merged Findings by Category
          </Typography>
          
          {!simulationResults || !simulationResults.merged || Object.keys(simulationResults.merged).length === 0 ? (
            <Alert severity="info" sx={{ mb: 3 }}>
              No categories with merged findings found
            </Alert>
          ) : (
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {Object.entries(simulationResults.merged || {}).map(([category, plugins]) => (
                <Grid item xs={12} key={category}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle1" color="primary.main" sx={{ fontWeight: 'bold' }} gutterBottom>
                        {category}
                      </Typography>
                      <Divider sx={{ mb: 2 }} />
                      
                      <Box sx={{ pl: 2 }}>
                        {Array.isArray(plugins) && plugins.length > 0 ? (
                          <>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                              {plugins.length} plugin{plugins.length !== 1 ? 's' : ''} in this category:
                            </Typography>
                            <List dense disablePadding>
                              {plugins.map((plugin, idx) => (
                                <ListItem key={idx} disablePadding sx={{ py: 0.5 }}>
                                  <ListItemText 
                                    primary={
                                      <Typography variant="body2">
                                        <strong>{plugin.id || plugin.ID}</strong> - {plugin.name || plugin.Name}
                                      </Typography>
                                    }
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No plugins in this category
                          </Typography>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          )}
          
          <Typography variant="h6" gutterBottom>
            Individual Findings ({(simulationResults && simulationResults.individual) ? simulationResults.individual.length : 0})
          </Typography>
          
          {!simulationResults || !simulationResults.individual || simulationResults.individual.length === 0 ? (
            <Alert severity="info">
              No individual findings found
            </Alert>
          ) : (
            <Card variant="outlined" sx={{ bgcolor: theme.palette.warning.dark, mb: 2 }}>
              <CardContent>
                <Typography variant="body2" color="warning.contrastText" paragraph>
                  These findings are not currently assigned to any category. You can add them to categories from the "Add Plugins" tab.
                </Typography>
                
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: theme.palette.background.paper }}>
                        <TableCell sx={{ fontWeight: 'bold' }}>Plugin ID</TableCell>
                        <TableCell sx={{ fontWeight: 'bold' }}>Name</TableCell>
                        <TableCell align="center" sx={{ fontWeight: 'bold' }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(simulationResults.individual || []).map((plugin, index) => (
                        <TableRow key={index} hover sx={{ '&:hover': { backgroundColor: theme.palette.action.hover } }}>
                          <TableCell>{plugin.id || plugin.ID || '-'}</TableCell>
                          <TableCell>{plugin.name || plugin.Name || 'Unknown'}</TableCell>
                          <TableCell align="center">
                            <Button
                              variant="outlined"
                              size="small"
                              color="primary"
                              startIcon={<AddIcon />}
                              onClick={() => {
                                setSimulationDialogOpen(false);
                                setActiveTab(1); // Switch to Add Plugins tab
                              }}
                            >
                              Manage
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          )}
          
          <Box display="flex" justifyContent="space-between" mt={2}>
            <Button
              variant="text"
              color="primary"
              onClick={() => {
                // If we have individual findings, update nonMergedPlugins and switch to Add Plugins tab
                if (simulationResults.individual && simulationResults.individual.length > 0) {
                  updateNonMergedPluginsFromSimulation(simulationResults.individual);
                  setActiveTab(1); // Switch to Add Plugins tab
                  setSimulationDialogOpen(false);
                }
              }}
              startIcon={<AddIcon />}
              disabled={!simulationResults.individual || simulationResults.individual.length === 0}
            >
              Go to Add Plugins
            </Button>
            <Button variant="contained" onClick={() => setSimulationDialogOpen(false)}>
              Close
            </Button>
          </Box>
        </DialogContent>
      </Dialog>
      
      {/* Loading Overlay */}
      {loading && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            zIndex: 9999,
          }}
        >
          <CircularProgress />
        </Box>
      )}
      
      {/* Notifications */}
      <Snackbar
        open={notification.open}
        autoHideDuration={6000}
        onClose={handleCloseNotification}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert 
          onClose={handleCloseNotification} 
          severity={notification.severity}
          variant="filled"
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default PluginManager;