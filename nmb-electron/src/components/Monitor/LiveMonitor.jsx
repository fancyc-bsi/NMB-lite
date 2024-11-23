import React, { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  LinearProgress,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import { Activity, AlertCircle, Check, Clock } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const mockMetrics = [
  { time: '10:00', cpu: 45, memory: 60 },
  { time: '10:05', cpu: 55, memory: 65 },
  { time: '10:10', cpu: 48, memory: 62 },
  { time: '10:15', cpu: 52, memory: 68 },
];

const LiveMonitor = () => {
  const [metrics, setMetrics] = useState(mockMetrics);
  const [activeScans, setActiveScans] = useState(2);
  const [progress, setProgress] = useState(45);

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>Live Monitor</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>System Metrics</Typography>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="cpu" 
                  stroke="#2196F3" 
                  name="CPU Usage (%)"
                />
                <Line 
                  type="monotone" 
                  dataKey="memory" 
                  stroke="#4CAF50" 
                  name="Memory Usage (%)"
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Active Scans</Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <Activity size={24} color="#2196F3" />
                </ListItemIcon>
                <ListItemText 
                  primary="Project Alpha" 
                  secondary={
                    <Box sx={{ width: '100%' }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                        <Typography variant="body2">Progress</Typography>
                        <Typography variant="body2">45%</Typography>
                      </Box>
                      <LinearProgress variant="determinate" value={45} />
                    </Box>
                  }
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Clock size={24} color="#FF9800" />
                </ListItemIcon>
                <ListItemText 
                  primary="Project Beta" 
                  secondary="Queued"
                />
              </ListItem>
            </List>
          </Paper>

          <Paper sx={{ p: 3, mt: 3 }}>
            <Typography variant="h6" gutterBottom>System Status</Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <Check size={24} color="#4CAF50" />
                </ListItemIcon>
                <ListItemText 
                  primary="API Connection" 
                  secondary="Connected"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Check size={24} color="#4CAF50" />
                </ListItemIcon>
                <ListItemText 
                  primary="Nessus Service" 
                  secondary="Running"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <AlertCircle size={24} color="#FF9800" />
                </ListItemIcon>
                <ListItemText 
                  primary="Memory Usage" 
                  secondary="65% (2.1GB / 3.2GB)"
                />
              </ListItem>
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default LiveMonitor;