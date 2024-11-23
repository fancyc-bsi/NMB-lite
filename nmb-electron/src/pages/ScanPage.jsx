// src/pages/ScanPage.jsx
import React from 'react';
import { Box } from '@mui/material';
import ScanForm from '../components/ScanForm';
import LogViewer from '../components/LogViewer/LogViewer';

const ScanPage = () => {
  return (
    <Box sx={{ p: 3 }}>
      <ScanForm />
      <LogViewer />
    </Box>
  );
};

export default ScanPage;