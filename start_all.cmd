@echo off
REM ============================================================
REM APIProxy full-stack launcher (double-click)
REM   window 1: Hypercorn main service  (http://127.0.0.1:5000)
REM   window 2: tls_front TLS front     (https://0.0.0.0:5443)
REM   window 3: cloudflared tunnel      (api.rsmc.cc.cd -> :5000)
REM NOTE: close old windows first, or ports 5000/5443 will conflict.
REM ============================================================
start "APIProxy-Hypercorn" /D E:\Code cmd /k python -m APIProxy
timeout /t 3 >nul
start "APIProxy-tls_front" /D E:\Code\APIProxy cmd /k python tls_front.py
timeout /t 2 >nul
start "APIProxy-tunnel" /D C:\Users\Administrator\.cloudflared cmd /k "D:\EdgeDownloads\cloudflared-windows-amd64.exe" tunnel --config config.yml --loglevel info run apiproxy
echo.
echo 3 windows launched. Check each window for logs.
pause
