#!/bin/bash

echo "cleaning out the bin directory"

rm -rf bin

cd nmb-electron

# Build the Electron app
npm run build:all

cd dist

mv NMB-Electron-1.0.0.AppImage ../../cmd/ui/linux/ui
mv "NMB-Electron 1.0.0.exe" ../../cmd/ui/windows/ui.exe

printf "Electron Build completed"

cd ../../

# Build the Go binary
echo ""
printf "Building the Go binary"
echo ""
# For Windows
GOOS=windows go build -o bin/nmb.exe ./cmd

# For Linux
GOOS=linux go build -o bin/nmb ./cmd

echo ""
printf "Go binary build completed"