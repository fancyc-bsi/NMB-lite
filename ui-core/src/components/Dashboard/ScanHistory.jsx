import React from 'react';
import { 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  Typography,
  Chip
} from '@mui/material';
import { Clock, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const mockData = [
  {
    id: 1,
    projectName: "Project Alpha",
    startTime: "2024-03-23 10:30",
    duration: "1h 30m",
    status: "completed",
    findings: 23
  },
  {
    id: 2,
    projectName: "Project Beta",
    startTime: "2024-03-23 12:45",
    duration: "45m",
    status: "in_progress",
    findings: 12
  },
  {
    id: 3,
    projectName: "Project Gamma",
    startTime: "2024-03-23 13:15",
    duration: "2h",
    status: "failed",
    findings: 0
  }
];

const getStatusChip = (status) => {
  const statusConfig = {
    completed: { color: 'success', icon: CheckCircle, text: 'Completed' },
    in_progress: { color: 'warning', icon: Clock, text: 'In Progress' },
    failed: { color: 'error', icon: XCircle, text: 'Failed' }
  };

  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <Chip
      icon={<Icon size={16} />}
      label={config.text}
      color={config.color}
      size="small"
    />
  );
};

const ScanHistory = () => {
  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Typography variant="h6" gutterBottom>Recent Scans</Typography>
      <TableContainer>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Project Name</TableCell>
              <TableCell>Start Time</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Findings</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {mockData.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell>{scan.projectName}</TableCell>
                <TableCell>{scan.startTime}</TableCell>
                <TableCell>{scan.duration}</TableCell>
                <TableCell>{getStatusChip(scan.status)}</TableCell>
                <TableCell>
                  <Chip
                    icon={<AlertTriangle size={16} />}
                    label={scan.findings}
                    color={scan.findings > 20 ? 'error' : 'warning'}
                    size="small"
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  );
};

export default ScanHistory;
