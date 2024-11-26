import React from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import { Activity, Shield, AlertTriangle, Check } from 'lucide-react';
import StatusCard from '../components/Dashboard/StatusCard';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const Dashboard = () => {
  const data = [
    { name: 'Jan', scans: 4 },
    { name: 'Feb', scans: 7 },
    { name: 'Mar', scans: 5 },
    { name: 'Apr', scans: 9 },
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3 }}>Dashboard</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <StatusCard
            title="Active Scans"
            value="3"
            icon={Activity}
            color="#4CAF50"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatusCard
            title="Vulnerabilities"
            value="127"
            icon={AlertTriangle}
            color="#FF9800"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatusCard
            title="Security Score"
            value="85%"
            icon={Shield}
            color="#2196F3"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatusCard
            title="Completed"
            value="24"
            icon={Check}
            color="#9C27B0"
          />
        </Grid>

        <Grid item xs={12}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>Scan Activity</Typography>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="scans" stroke="#2196F3" />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;