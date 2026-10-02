@echo off
REM Build & run the APIProxy Node realtime sidecar (TypeScript pillar).
REM See node/sidecar.ts for the multi-language split rationale.
cd /d %~dp0
where node >NUL 2>&1 || (echo Node.js not found on PATH & exit /b 1)
if not exist node_modules call npm install
call npm run build
call npm start
