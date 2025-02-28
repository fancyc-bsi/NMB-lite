import React from 'react';
import {
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Box,
  Typography,
  styled,
} from '@mui/material';
import {
  Scan,
  Settings,
  Shield,
  Activity,
  Terminal,
  Menu,
  Home,
  Image
} from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';

const DrawerWidth = 240;

const StyledDrawer = styled(Drawer)({
  width: DrawerWidth,
  flexShrink: 0,
  '& .MuiDrawer-paper': {
    width: DrawerWidth,
    boxSizing: 'border-box',
  },
});

const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  
  const menuItems = [
    { text: 'Dashboard', icon: <Home size={20} />, path: '/' },
    { text: 'NMB Manager', icon: <Scan size={20} />, path: '/scan' },
    { text: 'Nessus Control', icon: <Shield size={20} />, path: '/nessus' },
    { text: 'Screenshot Editor', icon: <Image size={20} />, path: '/screenshots' },
    { text: 'Plugin Manager', icon: <Activity size={20} />, path: '/plugins' },
    { text: 'Settings', icon: <Settings size={20} />, path: '/settings' },
  ];
  
  return (
    <StyledDrawer variant="permanent" anchor="left">
      <Box sx={{ p: 2, borderBottom: '1px solid rgba(255, 255, 255, 0.12)' }}>
        <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Terminal size={24} />
          BSTI
        </Typography>
      </Box>
      <List>
        {menuItems.map((item) => (
          <ListItem
            button
            key={item.text}
            onClick={() => navigate(item.path)}
            selected={location.pathname === item.path}
            sx={{
              my: 0.5,
              mx: 1,
              borderRadius: 1,
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
              },
            }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>{item.icon}</ListItemIcon>
            <ListItemText primary={item.text} />
          </ListItem>
        ))}
      </List>
    </StyledDrawer>
  );
};

export default Sidebar;