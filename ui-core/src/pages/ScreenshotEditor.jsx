import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Stack,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert
} from '@mui/material';
import { Crop, Save, FolderOpen, Image } from 'lucide-react';

import { OpenDirectoryDialog, ReadImageFile, SaveImageFile } from '../wailsjs/go/main/App';

const ScreenshotEditor = () => {
  const [directory, setDirectory] = useState('');
  const [imageList, setImageList] = useState([]);
  const [selectedImage, setSelectedImage] = useState(null);
  const [currentImageIndex, setCurrentImageIndex] = useState(-1);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notification, setNotification] = useState({ show: false, message: '', type: 'info' });
  const [cropMode, setCropMode] = useState(false);
  
  const imgRef = useRef(null);
  const cropBoxRef = useRef(null);
  const containerRef = useRef(null);
  
  const [cropBox, setCropBox] = useState({
    x: 0,
    y: 0,
    width: 0,
    height: 0,
    isDragging: false,
    isResizing: false,
    resizeHandle: '',
    startX: 0,
    startY: 0,
    originalWidth: 0,
    originalHeight: 0
  });

  const handleDirectorySelect = async () => {
    try {
      const selected = await OpenDirectoryDialog();
      if (selected) {
        setDirectory(selected);
        const files = await window.go.main.App.ListImageFilesInDirectory(selected);
        setImageList(files);
        setNotification({
          show: true,
          message: `Loaded ${files.length} images from ${selected}`,
          type: 'success'
        });
      }
    } catch (error) {
      setNotification({
        show: true,
        message: `Error loading directory: ${error.message}`,
        type: 'error'
      });
    }
  };

  const loadImage = async (index) => {
    try {
      const imagePath = imageList[index];
      const imageData = await ReadImageFile(imagePath);
      setSelectedImage({
        src: `data:image/png;base64,${imageData}`,
        path: imagePath
      });
      setCurrentImageIndex(index);
      setCropMode(false);
      
      // Reset crop box when loading new image
      if (imgRef.current) {
        const { width, height } = imgRef.current;
        setCropBox({
          x: width * 0.1,
          y: height * 0.1,
          width: width * 0.8,
          height: height * 0.8,
          isDragging: false,
          isResizing: false,
          resizeHandle: '',
          startX: 0,
          startY: 0,
          originalWidth: 0,
          originalHeight: 0
        });
      }
    } catch (error) {
      setNotification({
        show: true,
        message: `Error loading image: ${error.message}`,
        type: 'error'
      });
    }
  };

  const getRelativeCoordinates = (e) => {
    const container = containerRef.current.getBoundingClientRect();
    return {
      x: e.clientX - container.left,
      y: e.clientY - container.top
    };
  };

  const startDrag = (e) => {
    if (!cropMode) return;
    
    const { x, y } = getRelativeCoordinates(e);
    const cropRect = cropBoxRef.current.getBoundingClientRect();
    const containerRect = containerRef.current.getBoundingClientRect();
    
    // Check if clicking on resize handle
    const handleSize = 10;
    const isNearEdge = (coord, edge) => Math.abs(coord - edge) <= handleSize;
    
    const isNearLeft = isNearEdge(e.clientX, cropRect.left);
    const isNearRight = isNearEdge(e.clientX, cropRect.right);
    const isNearTop = isNearEdge(e.clientY, cropRect.top);
    const isNearBottom = isNearEdge(e.clientY, cropRect.bottom);
    
    if (isNearLeft || isNearRight || isNearTop || isNearBottom) {
      let handle = '';
      if (isNearTop) handle += 'n';
      if (isNearBottom) handle += 's';
      if (isNearLeft) handle += 'w';
      if (isNearRight) handle += 'e';
      
      setCropBox(prev => ({
        ...prev,
        isResizing: true,
        resizeHandle: handle,
        startX: x,
        startY: y,
        originalWidth: prev.width,
        originalHeight: prev.height
      }));
    } else {
      setCropBox(prev => ({
        ...prev,
        isDragging: true,
        startX: x - prev.x,
        startY: y - prev.y
      }));
    }
  };

  const onDrag = (e) => {
    if (!cropMode || (!cropBox.isDragging && !cropBox.isResizing)) return;
    
    const { x, y } = getRelativeCoordinates(e);
    const containerRect = containerRef.current.getBoundingClientRect();
    
    if (cropBox.isResizing) {
      const handle = cropBox.resizeHandle;
      let newX = cropBox.x;
      let newY = cropBox.y;
      let newWidth = cropBox.width;
      let newHeight = cropBox.height;
      
      const deltaX = x - cropBox.startX;
      const deltaY = y - cropBox.startY;
      
      if (handle.includes('e')) {
        newWidth = Math.max(50, cropBox.originalWidth + deltaX);
      }
      if (handle.includes('w')) {
        const maxLeftMove = cropBox.x + cropBox.width - 50;
        newX = Math.min(maxLeftMove, Math.max(0, cropBox.x + deltaX));
        newWidth = cropBox.x + cropBox.width - newX;
      }
      if (handle.includes('s')) {
        newHeight = Math.max(50, cropBox.originalHeight + deltaY);
      }
      if (handle.includes('n')) {
        const maxTopMove = cropBox.y + cropBox.height - 50;
        newY = Math.min(maxTopMove, Math.max(0, cropBox.y + deltaY));
        newHeight = cropBox.y + cropBox.height - newY;
      }
      
      // Ensure crop box stays within image bounds
      newWidth = Math.min(newWidth, containerRect.width - newX);
      newHeight = Math.min(newHeight, containerRect.height - newY);
      
      setCropBox(prev => ({
        ...prev,
        x: newX,
        y: newY,
        width: newWidth,
        height: newHeight
      }));
    } else if (cropBox.isDragging) {
      setCropBox(prev => ({
        ...prev,
        x: Math.max(0, Math.min(x - prev.startX, containerRect.width - prev.width)),
        y: Math.max(0, Math.min(y - prev.startY, containerRect.height - prev.height))
      }));
    }
  };

  const stopDrag = () => {
    setCropBox(prev => ({
      ...prev,
      isDragging: false,
      isResizing: false,
      resizeHandle: ''
    }));
  };

  const handleSave = async () => {
    if (!cropMode || !imgRef.current) return;
    setSaving(true);
    
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      // Calculate the scale between displayed image and natural image size
      const img = imgRef.current;
      const displayedImageRect = img.getBoundingClientRect();
      const scaleX = img.naturalWidth / displayedImageRect.width;
      const scaleY = img.naturalHeight / displayedImageRect.height;
      
      // Calculate offset of the image within the container (for centering)
      const containerRect = containerRef.current.getBoundingClientRect();
      const imageOffset = {
        x: (containerRect.width - displayedImageRect.width) / 2,
        y: (containerRect.height - displayedImageRect.height) / 2
      };
      
      // Adjust crop coordinates to account for image offset
      const adjustedCrop = {
        x: (cropBox.x - imageOffset.x) * scaleX,
        y: (cropBox.y - imageOffset.y) * scaleY,
        width: cropBox.width * scaleX,
        height: cropBox.height * scaleY
      };
      
      // Set canvas size to the crop dimensions
      canvas.width = adjustedCrop.width;
      canvas.height = adjustedCrop.height;
      
      // Draw the cropped portion
      ctx.drawImage(
        img,
        adjustedCrop.x,
        adjustedCrop.y,
        adjustedCrop.width,
        adjustedCrop.height,
        0,
        0,
        canvas.width,
        canvas.height
      );
      
      const base64Image = canvas.toDataURL('image/png').split(',')[1];
      await SaveImageFile(selectedImage.path, base64Image);
      
      setNotification({
        show: true,
        message: 'Image saved successfully',
        type: 'success'
      });
      
      setCropMode(false);
      await loadImage(currentImageIndex);
    } catch (error) {
      setNotification({
        show: true,
        message: `Error saving image: ${error.message}`,
        type: 'error'
      });
    } finally {
      setSaving(false);
      setDialogOpen(false);
    }
  };

  useEffect(() => {
    if (notification.show) {
      const timer = setTimeout(() => {
        setNotification({ ...notification, show: false });
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [notification]);

  useEffect(() => {
    if (imgRef.current && cropMode) {
      const { width, height } = imgRef.current;
      setCropBox({
        x: width * 0.1,
        y: height * 0.1,
        width: width * 0.8,
        height: height * 0.8,
        isDragging: false,
        isResizing: false,
        resizeHandle: '',
        startX: 0,
        startY: 0,
        originalWidth: 0,
        originalHeight: 0
      });
    }
  }, [cropMode]);

  const getCursorStyle = () => {
    if (!cropMode) return 'default';
    if (cropBox.isDragging) return 'move';
    if (cropBox.isResizing) {
      const handle = cropBox.resizeHandle;
      if (handle === 'n' || handle === 's') return 'ns-resize';
      if (handle === 'e' || handle === 'w') return 'ew-resize';
      if (handle === 'nw' || handle === 'se') return 'nwse-resize';
      if (handle === 'ne' || handle === 'sw') return 'nesw-resize';
    }
    return 'move';
  };

  return (
    <Box sx={{ p: 3, height: 'calc(100vh - 64px)' }}>
      <Paper elevation={3} sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
        <Typography variant="h5" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
          <Image size={24} />
          Screenshot Editor
        </Typography>

        {notification.show && (
          <Alert 
            severity={notification.type} 
            sx={{ mb: 2 }}
            onClose={() => setNotification({ ...notification, show: false })}
          >
            {notification.message}
          </Alert>
        )}

        <Box sx={{ display: 'flex', mb: 2 }}>
          <Button
            variant="contained"
            startIcon={<FolderOpen />}
            onClick={handleDirectorySelect}
            sx={{ mr: 2 }}
          >
            Open Directory
          </Button>
          {directory && (
            <Typography variant="body2" sx={{ alignSelf: 'center' }}>
              {directory}
            </Typography>
          )}
        </Box>

        <Box sx={{ display: 'flex', flex: 1, gap: 2 }}>
          <Paper
            elevation={1}
            sx={{
              width: 200,
              p: 1,
              overflow: 'auto',
              display: imageList.length ? 'block' : 'none'
            }}
          >
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Images ({imageList.length})
            </Typography>
            <Stack spacing={1}>
              {imageList.map((image, index) => (
                <Box
                  key={index}
                  sx={{
                    p: 1,
                    borderRadius: 1,
                    cursor: 'pointer',
                    bgcolor: currentImageIndex === index ? 'primary.main' : 'background.paper',
                    color: currentImageIndex === index ? 'primary.contrastText' : 'text.primary',
                    '&:hover': {
                      bgcolor: currentImageIndex === index ? 'primary.dark' : 'action.hover'
                    }
                  }}
                  onClick={() => loadImage(index)}
                >
                  <Typography variant="body2" noWrap>
                    {image.split('/').pop()}
                  </Typography>
                </Box>
              ))}
            </Stack>
          </Paper>

          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            {selectedImage ? (
              <>
                <Box sx={{ mb: 2, display: 'flex', gap: 1 }}>
                  <IconButton 
                    onClick={() => setCropMode(!cropMode)}
                    color={cropMode ? "primary" : "default"}
                    title="Toggle Crop Mode"
                  >
                    <Crop size={20} />
                  </IconButton>
                  <Button
                    variant="contained"
                    startIcon={<Save />}
                    onClick={() => setDialogOpen(true)}
                    disabled={!cropMode}
                  >
                    Save Cropped Image
                  </Button>
                </Box>

                <Box
                  ref={containerRef}
                  sx={{
                    position: 'relative',
                    flex: 1,
                    width: '100%',
                    overflow: 'hidden',
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    bgcolor: '#f5f5f5',
                    cursor: getCursorStyle()
                  }}
                  onMouseDown={startDrag}
                  onMouseMove={onDrag}
                  onMouseUp={stopDrag}
                  onMouseLeave={stopDrag}
                >
                  <img
                    ref={imgRef}
                    src={selectedImage.src}
                    alt="Selected"
                    style={{
                      maxWidth: '100%',
                      maxHeight: '100%',
                      objectFit: 'contain'
                    }}
                  />
                  {cropMode && (
                    <Box
                      ref={cropBoxRef}
                      sx={{
                        position: 'absolute',
                        border: '2px solid #1976d2',
                        left: cropBox.x,
                        top: cropBox.y,
                        width: cropBox.width,
                        height: cropBox.height
                      }}
                    />
                  )}
                </Box>
              </>
            ) : (
              <Box
                sx={{
                  flex: 1,
                  width: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  alignItems: 'center',
                  bgcolor: '#f5f5f5',
                }}
              >
                <Image size={64} strokeWidth={1} color="#aaa" />
                <Typography variant="body1" color="text.secondary" sx={{ mt: 2 }}>
                  {imageList.length
                    ? 'Select an image from the list'
                    : 'Open a directory to load images'}
                </Typography>
              </Box>
            )}
          </Box>
        </Box>
      </Paper>

      {/* Save Confirmation Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)}>
        <DialogTitle>Save Changes</DialogTitle>
        <DialogContent>
          <Typography>
            This will overwrite the original image. Are you sure you want to continue?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSave} color="primary" variant="contained" disabled={saving}>
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScreenshotEditor;