import React from 'react';
import { Paper, Typography, Box } from '@mui/material';
import { Activity } from 'lucide-react';

const StatusCard = ({ title, value, icon: Icon, color }) => {
  return (
    <Paper sx={{ p: 2, height: '100%' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Icon size={24} color={color} />
        <Typography variant="h6" sx={{ ml: 1 }}>{title}</Typography>
      </Box>
      <Typography variant="h4" sx={{ color }}>{value}</Typography>
    </Paper>
  );
};

export default StatusCard;