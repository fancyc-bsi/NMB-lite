#!/bin/bash
set -e

echo "🚀 Starting optimized build process..."

# Clean up old builds
echo "🧹 Cleaning up old builds..."
rm -rf bin/*
rm -rf ui-core/build
rm -rf build

# Optimize React build
echo "⚡ Optimizing React build..."
cd ui-core
GENERATE_SOURCEMAP=false REACT_APP_ENV=production npm run build
cd ..

# Build for Linux with optimizations
echo "🐧 Building for Linux..."
CGO_ENABLED=1 ~/go/bin/wails build -platform linux/amd64 -o ../bin/nmb -ldflags="-s -w"

# Build for Windows with optimizations
#echo "🪟 Building for Windows..."
#CGO_ENABLED=1 GOOS=windows GOARCH=amd64 ~/go/bin/wails build -platform windows/amd64 -o ../bin/nmb.exe -ldflags="-s -w"

echo "✅ Build complete!"
