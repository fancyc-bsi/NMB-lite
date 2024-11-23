#!/bin/bash

cd nmb-electron

npm run electron-pack

cd dist

mv NMB-Electron-1.0.0.AppImage ../../cmd/ui

printf "Build completed"
