// src/pages/SettingsPage.jsx
import React from 'react';
import { Box, Container, Typography } from '@mui/material';
import GeneralSettings from '../components/Settings/GeneralSettings';

// Make sure GeneralSettings is exported correctly
const SettingsPage = () => {
  return (
    <Box 
      component="main" 
      sx={{ 
        flexGrow: 1,
        p: 3,
        overflow: 'auto',
        mt: 8  // Add margin-top to account for the app bar
      }}
    >
      <Container maxWidth="lg">
        <Typography variant="h4" sx={{ mb: 4 }}>Settings</Typography>
        <GeneralSettings />
      </Container>
    </Box>
  );
};

export default SettingsPage;